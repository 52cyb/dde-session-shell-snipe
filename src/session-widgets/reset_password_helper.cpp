// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "reset_password_helper.h"
#include "authcommon.h"
#include "dconfig_helper.h"
#include "auth_module.h"
#include "constants.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QFile>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "dbusconstant.h"
#include "userinterface.h"

DCORE_USE_NAMESPACE

using namespace AuthCommon;

ResetPasswordHelper::ResetPasswordHelper(QObject *parent)
    : QObject(parent)
{
    // 创建常驻 DConfig 实例（生命周期跟随 this），监听 valueChanged 信号
    m_dconfig = DConfig::create("org.deepin.dde.control-center",
                                "org.deepin.dde.control-center.accounts",
                                "", this);
    if (m_dconfig) {
        connect(m_dconfig, &DConfig::valueChanged, this, &ResetPasswordHelper::onDConfigValueChanged);
        m_securityQuestionsConfig = m_dconfig->value("securityQuestions", QStringLiteral("Enabled")).toString();
    } else {
        qCWarning(DDE_SHELL) << "DConfig::create failed, use default Enabled";
        m_securityQuestionsConfig = QStringLiteral("Enabled");
    }
}

void ResetPasswordHelper::reloadDConfig()
{
    if (!m_dconfig) {
        qCWarning(DDE_SHELL) << "DConfig not available";
        return;
    }

    const QString newValue = m_dconfig->value("securityQuestions", QStringLiteral("Enabled")).toString();

    if (m_securityQuestionsConfig == newValue)
        return;

    const QString oldValue = m_securityQuestionsConfig;
    m_securityQuestionsConfig = newValue;

    // 缓存未就绪时只更新配置值，不触发 UI 更新（后续首次 compute 会读到最新值）
    if (!m_methodsCached)
        return;

    // 双向处理 DConfig 变更：
    // 1) → Hidden/Disabled：从缓存中同步移除 SecurityQuestionReset（不依赖异步查询）
    if ((newValue == "Hidden" || newValue == "Disabled")
        && (m_cachedResetMethods & SecurityQuestionReset)) {
        m_cachedResetMethods &= ~SecurityQuestionReset;
        emit availableMethodsChanged(m_cachedResetMethods);
        return;
    }

    // 2) ← Hidden/Disabled：标记安全问题缓存失效，触发异步重新查询 DBus
    if ((oldValue == "Hidden" || oldValue == "Disabled")
        && (newValue != "Hidden" && newValue != "Disabled")) {
        m_securityQuestionsChecked = false;
        m_securityQuestionsConfigured = false;
    }
}

void ResetPasswordHelper::onDConfigValueChanged(const QString &key)
{
    if (key != "securityQuestions")
        return;

    const QString oldConfig = m_securityQuestionsConfig;
    reloadDConfig();
    if (m_securityQuestionsConfig == oldConfig)
        return;

    if (m_methodsCached
        && m_securityQuestionsConfig != "Hidden"
        && m_securityQuestionsConfig != "Disabled") {
        refreshAvailableMethods();
    }
}

void ResetPasswordHelper::clearCache()
{
    m_securityQuestionsChecked = false;
    m_securityQuestionsConfigured = false;
    m_methodsCached = false;
    m_cachedResetMethods = NoResetMethod;
    m_secretKeyCached = false;
    m_secretKeyResult = false;
    m_pendingAsyncCalls = 0;
    m_isRefreshingMethods = false;

    m_deferRefresh = true;
    m_cacheGeneration++;
}

void ResetPasswordHelper::requestRefresh()
{
    m_deferRefresh = false;
    refreshAvailableMethods();
}

void ResetPasswordHelper::setCurrentUid(uid_t uid)
{
    clearCache();
    m_currentUid = uid;
}

bool ResetPasswordHelper::hasSecurityQuestionsConfigured()
{
    if (m_securityQuestionsChecked)
        return m_securityQuestionsConfigured;

    QDBusInterface accountsInter(DSS_DBUS::accountsService,
                                 QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                 DSS_DBUS::accountsUserInterface,
                                 QDBusConnection::systemBus());
    if (!accountsInter.isValid()) {
        return false;
    }

    QDBusReply<QList<int>> reply = accountsInter.call("GetSecretQuestions");
    if (!reply.isValid()) {
        qCWarning(DDE_SHELL) << "Get secret questions failed:" << reply.error().message();
        return false;
    }

    const QList<int> questions = reply.value();
    m_securityQuestionsConfigured = !(questions.size() == 1 && questions.first() == -1) && !questions.isEmpty();
    m_securityQuestionsChecked = true;
    return m_securityQuestionsConfigured;
}

int ResetPasswordHelper::computeAvailableMethods()
{
    int methods = NoResetMethod;

    m_securityQuestionsConfig = DConfigHelper::instance()->getConfig(
        "org.deepin.dde.control-center", "org.deepin.dde.control-center.accounts",
        "", "securityQuestions", QStringLiteral("Enabled")).toString();
    if (m_securityQuestionsConfig != "Hidden" && hasSecurityQuestionsConfigured()) {
        methods |= SecurityQuestionReset;
    }

    methods |= VerificationCodeReset;

    if (hasSecretKey()) {
        methods |= OfflineKeyReset;
    }

    return methods;
}

int ResetPasswordHelper::availableResetMethods()
{
    if (m_methodsCached) {
        return m_cachedResetMethods;
    }

    m_cachedResetMethods = computeAvailableMethods();
    m_methodsCached = true;
    return m_cachedResetMethods;
}

void ResetPasswordHelper::refreshAvailableMethods()
{
    if (m_deferRefresh) {
        return;
    }

    if (m_isRefreshingMethods) {
        return;
    }
    m_isRefreshingMethods = true;

    if (m_pendingAsyncCalls > 0) {
        m_isRefreshingMethods = false;
        return;
    }

    m_cachedResetMethods = NoResetMethod;
    m_methodsCached = false;
    m_secretKeyCached = false;
    m_secretKeyResult = false;
    m_pendingAsyncCalls = 0;
    m_securityQuestionsChecked = false;
    m_securityQuestionsConfigured = false;

    reloadDConfig();

    // 1. GetSecretQuestions
    if (m_securityQuestionsConfig != "Hidden") {
        QDBusInterface accountsInter(DSS_DBUS::accountsService,
                                     QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                     DSS_DBUS::accountsUserInterface,
                                     QDBusConnection::systemBus());
        if (accountsInter.isValid()) {
            m_pendingAsyncCalls++;
            QDBusPendingCall asyncCall = accountsInter.asyncCall("GetSecretQuestions");
            QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(asyncCall, this);
            connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, gen = m_cacheGeneration] {
                if (gen != m_cacheGeneration) { watcher->deleteLater(); return; }
                QDBusPendingReply<QList<int>> reply = *watcher;
                if (reply.isValid()) {
                    const QList<int> questions = reply.value();
                    m_securityQuestionsConfigured = !(questions.size() == 1 && questions.first() == -1) && !questions.isEmpty();
                } else {
                    qCWarning(DDE_SHELL) << "Async GetSecretQuestions failed:" << reply.error().message();
                }
                m_securityQuestionsChecked = true;
                watcher->deleteLater();
                onAsyncQueryFinished();
            });
        }
    }

    // 2. HasSecretKey
    {
        QDBusInterface accountsInter(DSS_DBUS::accountsService,
                                     QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                     DSS_DBUS::accountsUserInterface,
                                     QDBusConnection::systemBus());
        if (accountsInter.isValid()) {
            m_pendingAsyncCalls++;
            QDBusPendingCall asyncCall = accountsInter.asyncCall("HasSecretKey");
            QDBusPendingCallWatcher *watcher = new QDBusPendingCallWatcher(asyncCall, this);
            connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, gen = m_cacheGeneration] {
                if (gen != m_cacheGeneration) { watcher->deleteLater(); return; }
                QDBusPendingReply<bool> reply = *watcher;
                if (reply.isValid()) {
                    m_secretKeyResult = reply.value();
                } else {
                    qCWarning(DDE_SHELL) << "Async HasSecretKey failed:" << reply.error().message();
                }
                m_secretKeyCached = true;
                watcher->deleteLater();
                onAsyncQueryFinished();
            });
        }
    }

    if (m_pendingAsyncCalls == 0) {
        int methods = NoResetMethod;
        if (m_securityQuestionsConfig != "Hidden" && m_securityQuestionsConfigured)
            methods |= SecurityQuestionReset;
        methods |= VerificationCodeReset;
        if (m_secretKeyCached && m_secretKeyResult)
            methods |= OfflineKeyReset;

        m_cachedResetMethods = methods;
        m_methodsCached = true;
        emit availableMethodsChanged(m_cachedResetMethods);
    }
}

void ResetPasswordHelper::onAsyncQueryFinished(int)
{
    if (m_pendingAsyncCalls <= 0) {
        m_pendingAsyncCalls = 0;
        m_isRefreshingMethods = false;
        return;
    }

    m_pendingAsyncCalls--;

    if (m_pendingAsyncCalls > 0) {
        return;
    }

    int methods = NoResetMethod;

    if (m_securityQuestionsConfig != "Hidden" && m_securityQuestionsConfigured) {
        methods |= SecurityQuestionReset;
    }

    methods |= VerificationCodeReset;

    if (m_secretKeyCached && m_secretKeyResult) {
        methods |= OfflineKeyReset;
    }

    m_cachedResetMethods = methods;
    m_methodsCached = true;
    m_isRefreshingMethods = false;

    emit availableMethodsChanged(m_cachedResetMethods);
}

void ResetPasswordHelper::triggerResetPasswordByMethod(int method)
{
    if (method == VerificationCodeReset) {
        emit requestResetPasswordDialogStateChanged(true);
        org::deepin::dde::accounts1::User user(DSS_DBUS::accountsService,
                                               QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                               QDBusConnection::systemBus());
        auto reply = user.SetPassword("");
        reply.waitForFinished();
        if (reply.isError())
            qCWarning(DDE_SHELL) << "Reset password message error: " << reply.error().message();
        return;
    }

    if (method == OfflineKeyReset) {
        emit requestResetPasswordDialogStateChanged(true);
        const QString tabFile = QStringLiteral("/tmp/dde-reset-pwd-tab-%1").arg(m_currentUid);
        int fd = ::open(tabFile.toUtf8().constData(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
        if (fd >= 0) {
            ::write(fd, "offline", 7);
            ::close(fd);
        } else {
            qCWarning(DDE_SHELL) << "Failed to open" << tabFile << "error:" << strerror(errno);
        }
        QDBusInterface accountsInter(DSS_DBUS::accountsService,
                                     QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                     DSS_DBUS::accountsUserInterface,
                                     QDBusConnection::systemBus());
        QDBusReply<void> reply = accountsInter.call("SetPassword", "");
        if (reply.error().isValid())
            qCWarning(DDE_SHELL) << "Reset password message error: " << reply.error().message();
        return;
    }

    if (method == SecurityQuestionReset) {
        reloadDConfig();
        if (m_securityQuestionsConfig == "Disabled")
            return;
        emit requestResetPasswordDialogStateChanged(true);
        emit requestSecurityQuestionReset();
    }
}

QString ResetPasswordHelper::resetPasswordButtonText(int methods) const
{
    if (methods == VerificationCodeReset) {
        return tr("Reset by Verification Code");
    }

    if (methods == SecurityQuestionReset) {
        return tr("Reset by Security Questions");
    }

    if (methods == OfflineKeyReset) {
        return tr("Reset by Offline Key");
    }

    return tr("Reset Password");
}

bool ResetPasswordHelper::isShowResetPasswordMessage() const
{
    return QFile::exists(DEEPIN_DEEPINID_DAEMON_PATH) && QFile::exists(ResetPassword_Exe_Path) && m_currentUid <= 9999 && !IsCommunitySystem;
}

QString ResetPasswordHelper::securityQuestionsConfig()
{
    if (m_dconfig) {
        m_securityQuestionsConfig = m_dconfig->value("securityQuestions", QStringLiteral("Enabled")).toString();
    }
    return m_securityQuestionsConfig;
}

bool ResetPasswordHelper::hasSecretKey()
{
    if (m_secretKeyCached)
        return m_secretKeyResult;

    QDBusInterface accountsInter(DSS_DBUS::accountsService,
                                 QString(DSS_DBUS::accountsUserPath).arg(m_currentUid),
                                 DSS_DBUS::accountsUserInterface,
                                 QDBusConnection::systemBus());
    if (!accountsInter.isValid()) {
        m_secretKeyCached = true;
        m_secretKeyResult = false;
        return false;
    }

    QDBusReply<bool> reply = accountsInter.call("HasSecretKey");
    if (!reply.isValid()) {
        qCWarning(DDE_SHELL) << "HasSecretKey failed:" << reply.error().message();
        m_secretKeyCached = true;
        m_secretKeyResult = false;
        return false;
    }

    m_secretKeyResult = reply.value();
    m_secretKeyCached = true;
    return m_secretKeyResult;
}

