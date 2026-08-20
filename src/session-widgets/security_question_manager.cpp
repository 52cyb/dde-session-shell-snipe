// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "security_question_manager.h"
#include "sessionbasemodel.h"
#include "authcommon.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDateTime>
#include <QDir>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QTimer>

#include "dbusconstant.h"

SecurityQuestionManager::SecurityQuestionManager(SessionBaseModel *model, QObject *parent)
    : QObject(parent)
    , m_model(model)
{
}

SecurityQuestionManager::~SecurityQuestionManager()
{
    if (m_imePollTimer) {
        m_imePollTimer->stop();
    }
    m_imeStage = 0;
    if (m_securityQuestionHelperProcess) {
        m_securityQuestionHelperProcess->disconnect();
    }
    m_flowInProgress = false;
    cleanupSecurityQuestionHelper();
    stopSecurityQuestionIMEInfrastructure();
}

void SecurityQuestionManager::cleanup()
{
    if (m_imePollTimer) {
        m_imePollTimer->stop();
    }
    m_imeStage = 0;
    if (m_securityQuestionHelperProcess) {
        m_securityQuestionHelperProcess->disconnect();
    }
    m_flowInProgress = false;
    cleanupSecurityQuestionHelper();
    stopSecurityQuestionIMEInfrastructure();
}

void SecurityQuestionManager::resetDialogState()
{
    if (m_imePollTimer) {
        m_imePollTimer->stop();
    }
    m_imeStage = 0;
    m_flowInProgress = false;
    m_hasResetPasswordDialog = false;
    emit resetPasswordDialogStateChanged(false);
    emit requestTryGrabKeyboard(false);
}

void SecurityQuestionManager::setDialogState(bool visible)
{
    m_hasResetPasswordDialog = visible;
    emit resetPasswordDialogStateChanged(visible);
}

void SecurityQuestionManager::handleRequestReset(uid_t uid)
{
    qCInfo(DDE_SHELL) << "Security question reset requested for user:"
                       << m_model->currentUser()->name()
                       << "uid:" << uid;

    QDBusInterface userInter(DSS_DBUS::accountsService,
                             QString(DSS_DBUS::accountsUserPath).arg(uid),
                             DSS_DBUS::accountsUserInterface,
                             QDBusConnection::systemBus());
    QDBusReply<QList<int>> questionsReply = userInter.call("GetSecretQuestions");

    if (!questionsReply.isValid() || (questionsReply.value().size() == 1 && questionsReply.value().first() == -1)) {
        qCWarning(DDE_SHELL) << "No security questions set for current user, skip reset password";
        return;
    }

    QJsonArray questionArray;
    for (const int index : questionsReply.value()) {
        questionArray.append(index);
    }

    bool sqLocked = false;
    int sqMaxTries = 0;
    int sqNumFailures = 0;
    QString sqUnlockTime;
    QDBusMessage sqLimitsMsg = QDBusMessage::createMethodCall(
        DSS_DBUS::accountsService,
        QString(DSS_DBUS::accountsUserPath).arg(uid),
        DSS_DBUS::accountsUserInterface,
        "GetSqLimits");
    QDBusMessage sqLimitsReply = QDBusConnection::systemBus().call(sqLimitsMsg);
    if (sqLimitsReply.type() == QDBusMessage::ReplyMessage && sqLimitsReply.arguments().size() >= 4) {
        sqLocked = sqLimitsReply.arguments().at(0).toBool();
        sqMaxTries = sqLimitsReply.arguments().at(1).toInt();
        sqNumFailures = sqLimitsReply.arguments().at(2).toInt();
        sqUnlockTime = sqLimitsReply.arguments().at(3).toString();
    }

    if (sqMaxTries <= 0)
        sqMaxTries = 10;

    int remainingAttempts = sqMaxTries - sqNumFailures;
    if (sqLocked) remainingAttempts = 0;

    qCInfo(DDE_SHELL) << "Security question limits: locked=" << sqLocked
                       << "maxTries=" << sqMaxTries << "numFailures=" << sqNumFailures
                       << "remainingAttempts=" << remainingAttempts
                       << "unlockTime=" << sqUnlockTime;

    QJsonObject payload {
        { QStringLiteral("questions"), questionArray },
        { QStringLiteral("isLock"), m_model->appType() == AuthCommon::Lock },
        { QStringLiteral("uid"), static_cast<int>(uid) },
        { QStringLiteral("userName"), m_model->currentUser()->name() },
        { QStringLiteral("fullName"), m_model->currentUser()->displayName() },
        { QStringLiteral("remainingAttempts"), remainingAttempts },
        { QStringLiteral("maxTries"), sqMaxTries },
        { QStringLiteral("locked"), sqLocked },
        { QStringLiteral("unlockTime"), sqUnlockTime }
    };

    const QByteArray payloadData = QJsonDocument(payload).toJson(QJsonDocument::Compact)
        .toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

    startSecurityQuestionFlow(QString::fromUtf8(payloadData));
}

void SecurityQuestionManager::startSecurityQuestionFlow(const QString &payloadData)
{
    if (m_flowInProgress) {
        qCWarning(DDE_SHELL) << "Security question flow already in progress, skipping";
        return;
    }

    const bool isLock = (m_model->appType() == AuthCommon::Lock);

    m_flowInProgress = true;
    m_hasResetPasswordDialog = true;
    m_pendingPayload = payloadData;
    emit resetPasswordDialogStateChanged(true);

    if (isLock) {
        qCInfo(DDE_SHELL) << "Security question (lock): using existing session bus for IME,"
                           << "bus:" << QProcessEnvironment::systemEnvironment().value("DBUS_SESSION_BUS_ADDRESS");
        startHelperAfterIme();
    } else {
        qCInfo(DDE_SHELL) << "Security question (greeter): starting IME infrastructure asynchronously";
        startImeAsync();
    }
}

void SecurityQuestionManager::startImeAsync()
{
    stopSecurityQuestionIMEInfrastructure();
    m_imeStage = 0;
    m_imePollCount = 0;

    const QString dbusDaemon = QStandardPaths::findExecutable(QStringLiteral("dbus-daemon"));
    if (dbusDaemon.isEmpty()) {
        qCWarning(DDE_SHELL) << "dbus-daemon not found, cannot start IME infrastructure";
        resetDialogState();
        return;
    }

    auto *busProcess = new QProcess(this);
    busProcess->setProcessChannelMode(QProcess::MergedChannels);
    m_securityQuestionBusProcess = busProcess;

    connect(busProcess, &QProcess::started, this, [this, busProcess]() {
        if (m_securityQuestionBusProcess != busProcess) return;
        if (m_imeStage < 1) m_imeStage = 1;
    });
    connect(busProcess, &QProcess::readyReadStandardOutput, this, [this, busProcess]() {
        if (m_securityQuestionBusProcess != busProcess) return;
        if (m_imeStage > 1) return;
        const QString address = QString::fromLocal8Bit(busProcess->readAllStandardOutput().split('\n').first()).trimmed();
        if (address.isEmpty()) return;
        m_imeStage = 2;
        m_securityQuestionBusAddress = address;
        continueImeSetup();
    });
    connect(busProcess, QOverload<QProcess::ProcessError>::of(&QProcess::errorOccurred), this, [this, busProcess](QProcess::ProcessError) {
        if (m_securityQuestionBusProcess != busProcess) return;
        qCWarning(DDE_SHELL) << "Failed to start private session bus";
        stopSecurityQuestionIMEInfrastructure();
        m_imeStage = -1;
        resetDialogState();
    });

    busProcess->start(dbusDaemon, QStringList()
                      << QStringLiteral("--session")
                      << QStringLiteral("--nofork")
                      << QStringLiteral("--print-address=1"));

    // 超时保护：与 gerrit 保持一致，3000ms 内未完成 IME 搭建则判定超时。
    // 注：fcitx-remote 就绪轮询上限仍为 5s，但受 3000ms 全局超时约束，
    // 实际轮询窗口被截断，行为与 gerrit 一致。
    const QPointer<QProcess> busGuard(busProcess);
    QTimer::singleShot(3000, this, [this, busGuard] {
        if (busGuard && m_securityQuestionBusProcess == busGuard) {
            onImeTimeout();
        }
    });
}

void SecurityQuestionManager::continueImeSetup()
{
    if (m_imeStage == 2) {
        qCInfo(DDE_SHELL) << "Private session bus ready, address:" << m_securityQuestionBusAddress
                           << "original bus:" << QProcessEnvironment::systemEnvironment().value("DBUS_SESSION_BUS_ADDRESS");

        m_fcitxExecutable = QStandardPaths::findExecutable(QStringLiteral("fcitx5"));
        m_fcitxRemoteExecutable = QStandardPaths::findExecutable(QStringLiteral("fcitx5-remote"));
        bool isFcitx5 = !m_fcitxExecutable.isEmpty() && !m_fcitxRemoteExecutable.isEmpty();
        if (!isFcitx5) {
            m_fcitxExecutable = QStandardPaths::findExecutable(QStringLiteral("fcitx"));
            m_fcitxRemoteExecutable = QStandardPaths::findExecutable(QStringLiteral("fcitx-remote"));
        }
        if (m_fcitxExecutable.isEmpty() || m_fcitxRemoteExecutable.isEmpty()) {
            qCWarning(DDE_SHELL) << "fcitx executable or remote command not found";
            stopSecurityQuestionIMEInfrastructure();
            m_imeStage = -1;
            resetDialogState();
            return;
        }

        auto *fcitxProcess = new QProcess(this);
        QProcessEnvironment fcitxEnv = QProcessEnvironment::systemEnvironment();
        fcitxEnv.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
        fcitxEnv.insert(QStringLiteral("DBUS_FATAL_WARNINGS"), QStringLiteral("0"));
        fcitxProcess->setProcessEnvironment(fcitxEnv);
        m_securityQuestionFcitxProcess = fcitxProcess;

        connect(fcitxProcess, &QProcess::started, this, [this, fcitxProcess]() {
            if (m_securityQuestionFcitxProcess != fcitxProcess) return;
            m_imeStage = 3;
            m_imePollCount = 0;
            if (!m_imePollTimer) {
                m_imePollTimer = new QTimer(this);
                m_imePollTimer->setInterval(300);
                connect(m_imePollTimer, &QTimer::timeout, this, &SecurityQuestionManager::continueImeSetup);
            }
            m_imePollTimer->start();
        });
        connect(fcitxProcess, QOverload<QProcess::ProcessError>::of(&QProcess::errorOccurred), this, [this, fcitxProcess](QProcess::ProcessError) {
            if (m_securityQuestionFcitxProcess != fcitxProcess) return;
            qCWarning(DDE_SHELL) << "Failed to start fallback fcitx";
            stopSecurityQuestionIMEInfrastructure();
            m_imeStage = -1;
            resetDialogState();
        });
        connect(fcitxProcess, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, fcitxProcess](int exitCode, QProcess::ExitStatus exitStatus) {
            if (m_securityQuestionFcitxProcess != fcitxProcess) return;
            if (m_imeStage >= 3 && m_flowInProgress) {
                qCWarning(DDE_SHELL) << "Security question fcitx exited unexpectedly, exitCode:"
                                     << exitCode << "exitStatus:" << exitStatus;
            }
        });

        // daemonize 参数差异：fcitx5 用 -D，fcitx4 用 -d
        const QString daemonFlag = isFcitx5 ? QStringLiteral("-D") : QStringLiteral("-d");
        fcitxProcess->start(QStringLiteral("sh"),
                            QStringList() << QStringLiteral("-c")
                            << QStringLiteral("ulimit -c 0 && exec ")
                               + m_fcitxExecutable + QStringLiteral(" ") + daemonFlag);
        return;
    }

    if (m_imeStage == 3) {
        if (m_imePollCount * 300 >= 5000) {
            m_imePollTimer->stop();
            qCWarning(DDE_SHELL) << "Fallback fcitx did not become reachable within 5s";
            m_imeStage = 4;
            startHelperAfterIme();
            return;
        }

        m_imePollCount++;
        if (m_fcitxRemoteCheck) {
            QProcess *previousCheck = m_fcitxRemoteCheck;
            m_fcitxRemoteCheck = nullptr;
            previousCheck->disconnect(this);
            previousCheck->kill();
            previousCheck->waitForFinished(500);
            previousCheck->deleteLater();
        }
        auto *remoteCheck = new QProcess(this);
        m_fcitxRemoteCheck = remoteCheck;
        QProcessEnvironment remoteEnv = QProcessEnvironment::systemEnvironment();
        remoteEnv.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
        remoteCheck->setProcessEnvironment(remoteEnv);
        remoteCheck->setProgram(m_fcitxRemoteExecutable);
        remoteCheck->setArguments(QStringList());

        connect(remoteCheck, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this, remoteCheck]() {
            const QString state = QString::fromLocal8Bit(remoteCheck->readAllStandardOutput().trimmed());
            remoteCheck->deleteLater();
            if (m_fcitxRemoteCheck == remoteCheck) {
                m_fcitxRemoteCheck = nullptr;
            }
            if (m_imeStage != 3) return;
            if (!state.isEmpty()) {
                m_imePollTimer->stop();
                qCInfo(DDE_SHELL) << "Fallback fcitx is reachable, state:" << state;
                m_imeStage = 4;
                startHelperAfterIme();
            }
        });

        remoteCheck->start();
        return;
    }
}

void SecurityQuestionManager::onImeTimeout()
{
    if (m_imeStage >= 0 && m_imeStage < 4) {
        qCWarning(DDE_SHELL) << "IME infrastructure setup timed out, stage:" << m_imeStage;
        stopSecurityQuestionIMEInfrastructure();
        m_imeStage = -1;
        resetDialogState();
    }
}

void SecurityQuestionManager::startHelperAfterIme()
{
    if (!startSecurityQuestionHelper(m_pendingPayload)) {
        qCWarning(DDE_SHELL) << "Failed to start security question helper process";
        stopSecurityQuestionIMEInfrastructure();
        resetDialogState();
        return;
    }

    if (!m_securityQuestionHelperProcess) {
        qCWarning(DDE_SHELL) << "Security question helper process is null after start";
        cleanupSecurityQuestionHelper();
        stopSecurityQuestionIMEInfrastructure();
        resetDialogState();
        return;
    }

    connect(m_securityQuestionHelperProcess, qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this, &SecurityQuestionManager::onHelperFinished);
    connect(m_securityQuestionHelperProcess, &QProcess::errorOccurred,
            this, &SecurityQuestionManager::onHelperError);

    m_securityQuestionHelperProcess->start();
    qCInfo(DDE_SHELL) << "Security question helper started asynchronously";
}

void SecurityQuestionManager::onHelperFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (!m_flowInProgress) return;
    m_flowInProgress = false;

    const QByteArray stdOut = m_securityQuestionHelperProcess->readAllStandardOutput().trimmed();
    const QByteArray stdErr = m_securityQuestionHelperProcess->readAllStandardError().trimmed();
    qCInfo(DDE_SHELL) << "Security question helper finished, exitCode:" << exitCode << "exitStatus:" << exitStatus;
    if (!stdErr.isEmpty()) {
        qCInfo(DDE_SHELL) << "Security question helper stderr:\n" << QString::fromLocal8Bit(stdErr);
    }

    stopSecurityQuestionIMEInfrastructure();

    cleanupSecurityQuestionHelper();
    m_hasResetPasswordDialog = false;
    emit resetPasswordDialogStateChanged(false);
    emit requestTryGrabKeyboard(false);

    if (stdOut.isEmpty()) {
        qCInfo(DDE_SHELL) << "Security question dialog cancelled";
        emit resetPasswordComplete(false);
        return;
    }

    QJsonParseError parseError;
    const QJsonDocument resultDoc = QJsonDocument::fromJson(stdOut, &parseError);
    if (parseError.error != QJsonParseError::NoError || !resultDoc.isObject()) {
        qCWarning(DDE_SHELL) << "Failed to parse security question helper output:" << parseError.errorString();
        emit resetPasswordComplete(false);
        return;
    }

    const QJsonObject result = resultDoc.object();

    if (result.value(QStringLiteral("passwordChanged")).toBool()) {
        qCInfo(DDE_SHELL) << "Security question reset: password changed successfully";
        m_model->setPasswordResetByRequest(false);
        emit resetPasswordComplete(true);
        return;
    }

    if (!result.value(QStringLiteral("accepted")).toBool()) {
        qCInfo(DDE_SHELL) << "Security question dialog cancelled";
        emit resetPasswordComplete(false);
        return;
    }

    if (!result.value(QStringLiteral("verified")).toBool(true)) {
        qCWarning(DDE_SHELL) << "Security question verification failed in helper";
        emit resetPasswordComplete(false);
        return;
    }

    emit resetPasswordComplete(false);
}

void SecurityQuestionManager::onHelperError(QProcess::ProcessError error)
{
    if (!m_flowInProgress) return;

    qCWarning(DDE_SHELL) << "Security question helper error:" << error;
    if (m_securityQuestionHelperProcess) {
        m_securityQuestionHelperProcess->disconnect();
    }
    stopSecurityQuestionIMEInfrastructure();
    cleanupSecurityQuestionHelper();
    resetDialogState();
    emit resetPasswordComplete(false);
}

QString SecurityQuestionManager::securityQuestionHelperExecutable() const
{
    return QStandardPaths::findExecutable(QStringLiteral("dde-security-question-helper"));
}

bool SecurityQuestionManager::startSecurityQuestionHelper(const QString &payload)
{
    cleanupSecurityQuestionHelper();

    const QString helperExecutable = securityQuestionHelperExecutable();
    const QStringList helperArgs = {QStringLiteral("--payload"), payload};
    if (helperExecutable.isEmpty()) {
        return false;
    }

    auto *process = new QProcess(this);
    process->setProcessChannelMode(QProcess::SeparateChannels);

    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();

    // 按系统实际输入法动态决定 IM_MODULE（与 helper 内 detectInputMethodBackend 探测一致）
    // 仅 fcitx5 时注入 fcitx5，否则回退 fcitx，保证 helper 能加载对应的 Qt 输入法插件
    QString imModule = QStringLiteral("fcitx");
    if (!QStandardPaths::findExecutable(QStringLiteral("fcitx5")).isEmpty()) {
        imModule = QStringLiteral("fcitx5");
    }

    environment.insert(QStringLiteral("GTK_IM_MODULE"), imModule);
    environment.insert(QStringLiteral("QT_IM_MODULE"), imModule);
    environment.insert(QStringLiteral("XMODIFIERS"), QStringLiteral("@im=%1").arg(imModule));
    environment.insert(QStringLiteral("INPUT_METHOD"), imModule);

    if (m_model->appType() != AuthCommon::Lock && !m_securityQuestionBusAddress.isEmpty()) {
        environment.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
    }

    process->setProcessEnvironment(environment);
    process->setProgram(helperExecutable);
    process->setArguments(helperArgs);

    m_securityQuestionHelperProcess = process;
    return true;
}

void SecurityQuestionManager::cleanupSecurityQuestionHelper()
{
    if (m_securityQuestionHelperProcess) {
        if (m_securityQuestionHelperProcess->state() != QProcess::NotRunning) {
            const qint64 pid = m_securityQuestionHelperProcess->processId();
            qCInfo(DDE_SHELL) << "Cleaning up security question helper, pid:" << pid;

            m_securityQuestionHelperProcess->terminate();
            if (!m_securityQuestionHelperProcess->waitForFinished(2000)) {
                m_securityQuestionHelperProcess->kill();
                m_securityQuestionHelperProcess->waitForFinished(1000);
            }
            qCInfo(DDE_SHELL) << "Security question helper process exited, pid:" << pid;
        }
        m_securityQuestionHelperProcess->deleteLater();
        m_securityQuestionHelperProcess = nullptr;

        if (m_securityQuestionFcitxAclSet) {
            setFcitxSocketAcl(QStringLiteral("deepin-daemon"), m_securityQuestionFcitxAclUid, false);
            m_securityQuestionFcitxAclSet = false;
            m_securityQuestionFcitxAclUid = 0;
        }
    }
}

void SecurityQuestionManager::stopSecurityQuestionIMEInfrastructure()
{
    if (m_imePollTimer) {
        m_imePollTimer->stop();
    }

    if (m_fcitxRemoteCheck) {
        QProcess *remoteCheck = m_fcitxRemoteCheck;
        m_fcitxRemoteCheck = nullptr;
        remoteCheck->disconnect(this);
        remoteCheck->kill();
        remoteCheck->waitForFinished(500);
        remoteCheck->deleteLater();
    }

    if (m_securityQuestionFcitxProcess) {
        m_securityQuestionFcitxProcess->disconnect(this);
        if (m_securityQuestionFcitxProcess->state() != QProcess::NotRunning) {
            m_securityQuestionFcitxProcess->kill();
            m_securityQuestionFcitxProcess->waitForFinished(1000);
            qCInfo(DDE_SHELL) << "Stopped fallback fcitx";
        }
        m_securityQuestionFcitxProcess->deleteLater();
        m_securityQuestionFcitxProcess = nullptr;
    }

    if (m_securityQuestionBusProcess) {
        m_securityQuestionBusProcess->disconnect(this);
        if (m_securityQuestionBusProcess->state() != QProcess::NotRunning) {
            m_securityQuestionBusProcess->terminate();
            if (!m_securityQuestionBusProcess->waitForFinished(1000)) {
                m_securityQuestionBusProcess->kill();
                m_securityQuestionBusProcess->waitForFinished(1000);
            }
            qCInfo(DDE_SHELL) << "Stopped private session bus";
        }
        m_securityQuestionBusProcess->deleteLater();
        m_securityQuestionBusProcess = nullptr;
    }

    m_securityQuestionBusAddress.clear();
    m_fcitxExecutable.clear();
    m_fcitxRemoteExecutable.clear();
}

void SecurityQuestionManager::setFcitxSocketAcl(const QString &user, quint32 uid, bool enable)
{
    const QString flag = enable ? QStringLiteral("-m") : QStringLiteral("-x");
    const QString perms = enable ? QStringLiteral(":rwx") : QString();
    const QString runDir = QStringLiteral("/run/user/%1").arg(uid);

    for (const QString &subdir : {QStringLiteral("fcitx5"), QStringLiteral("fcitx")}) {
        const QString socketDir = runDir + QLatin1Char('/') + subdir;
        if (!QDir(socketDir).exists()) {
            continue;
        }
        QProcess setfacl;
        setfacl.start(QStringLiteral("setfacl"),
                      {flag, QStringLiteral("u:%1%2").arg(user, perms), socketDir});
        setfacl.waitForFinished(3000);
        if (setfacl.exitCode() != 0) {
            qCWarning(DDE_SHELL) << "setfacl" << flag << "on" << socketDir << "failed:"
                                 << QString::fromLocal8Bit(setfacl.readAllStandardError()).trimmed();
        }
    }
}
