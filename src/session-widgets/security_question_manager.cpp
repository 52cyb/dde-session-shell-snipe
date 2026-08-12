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
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QThread>
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

    connect(busProcess, &QProcess::started, this, [this]() {
        if (m_imeStage < 1) m_imeStage = 1;
    });
    connect(busProcess, &QProcess::readyReadStandardOutput, this, [this, busProcess]() {
        if (m_imeStage > 1) return;
        const QString address = QString::fromLocal8Bit(busProcess->readAllStandardOutput().split('\n').first()).trimmed();
        if (address.isEmpty()) return;
        m_imeStage = 2;
        m_securityQuestionBusAddress = address;
        m_securityQuestionBusProcess = busProcess;
        continueImeSetup();
    });
    connect(busProcess, QOverload<QProcess::ProcessError>::of(&QProcess::errorOccurred), this, [this](QProcess::ProcessError) {
        qCWarning(DDE_SHELL) << "Failed to start private session bus";
        stopSecurityQuestionIMEInfrastructure();
        m_imeStage = -1;
        resetDialogState();
    });

    busProcess->start(dbusDaemon, QStringList()
                      << QStringLiteral("--session")
                      << QStringLiteral("--nofork")
                      << QStringLiteral("--print-address=1"));

    QTimer::singleShot(3000, this, &SecurityQuestionManager::onImeTimeout);
}

void SecurityQuestionManager::continueImeSetup()
{
    if (m_imeStage == 2) {
        qCInfo(DDE_SHELL) << "Private session bus ready, address:" << m_securityQuestionBusAddress
                           << "original bus:" << QProcessEnvironment::systemEnvironment().value("DBUS_SESSION_BUS_ADDRESS");

        const QString fcitxBin = QStandardPaths::findExecutable(QStringLiteral("fcitx"));
        if (fcitxBin.isEmpty()) {
            qCWarning(DDE_SHELL) << "fcitx not found, cannot start fallback IME";
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

        connect(fcitxProcess, &QProcess::started, this, [this]() {
            m_imeStage = 3;
            m_imePollCount = 0;
            if (!m_imePollTimer) {
                m_imePollTimer = new QTimer(this);
                m_imePollTimer->setInterval(300);
                connect(m_imePollTimer, &QTimer::timeout, this, &SecurityQuestionManager::continueImeSetup);
            }
            m_imePollTimer->start();
        });
        connect(fcitxProcess, QOverload<QProcess::ProcessError>::of(&QProcess::errorOccurred), this, [this](QProcess::ProcessError) {
            qCWarning(DDE_SHELL) << "Failed to start fallback fcitx";
            stopSecurityQuestionIMEInfrastructure();
            m_imeStage = -1;
            resetDialogState();
        });

        fcitxProcess->start(QStringLiteral("sh"), QStringList()
            << QStringLiteral("-c")
            << QStringLiteral("ulimit -c 0 && exec ") + fcitxBin + QStringLiteral(" -d"));
        m_securityQuestionFcitxProcess = fcitxProcess;
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
            m_fcitxRemoteCheck->kill();
            m_fcitxRemoteCheck->waitForFinished(500);
            m_fcitxRemoteCheck->deleteLater();
        }
        m_fcitxRemoteCheck = new QProcess(this);
        QProcessEnvironment remoteEnv = QProcessEnvironment::systemEnvironment();
        remoteEnv.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
        m_fcitxRemoteCheck->setProcessEnvironment(remoteEnv);
        m_fcitxRemoteCheck->setProgram(QStringLiteral("fcitx-remote"));
        m_fcitxRemoteCheck->setArguments(QStringList());

        connect(m_fcitxRemoteCheck, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this]() {
            if (m_imeStage != 3) return;
            const QString state = QString::fromLocal8Bit(m_fcitxRemoteCheck->readAllStandardOutput().trimmed());
            m_fcitxRemoteCheck->deleteLater();
            m_fcitxRemoteCheck = nullptr;
            if (!state.isEmpty()) {
                m_imePollTimer->stop();
                qCInfo(DDE_SHELL) << "Fallback fcitx is reachable, state:" << state;
                m_imeStage = 4;
                startHelperAfterIme();
            }
        });

        m_fcitxRemoteCheck->start();
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
        resetDialogState();
        return;
    }

    if (!m_securityQuestionHelperProcess) {
        qCWarning(DDE_SHELL) << "Security question helper process is null after start";
        cleanupSecurityQuestionHelper();
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
    environment.insert(QStringLiteral("GTK_IM_MODULE"), QStringLiteral("fcitx"));
    environment.insert(QStringLiteral("QT_IM_MODULE"), QStringLiteral("fcitx"));
    environment.insert(QStringLiteral("XMODIFIERS"), QStringLiteral("@im=fcitx"));
    environment.insert(QStringLiteral("INPUT_METHOD"), QStringLiteral("fcitx"));

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

bool SecurityQuestionManager::startSecurityQuestionIMEInfrastructure()
{
    stopSecurityQuestionIMEInfrastructure();

    const QString dbusDaemon = QStandardPaths::findExecutable(QStringLiteral("dbus-daemon"));
    if (dbusDaemon.isEmpty()) {
        qCWarning(DDE_SHELL) << "dbus-daemon not found, cannot start IME infrastructure";
        return false;
    }

    auto *busProcess = new QProcess(this);
    busProcess->setProcessChannelMode(QProcess::MergedChannels);
    busProcess->start(dbusDaemon, QStringList()
                      << QStringLiteral("--session")
                      << QStringLiteral("--nofork")
                      << QStringLiteral("--print-address=1"));
    if (!busProcess->waitForStarted(2000)) {
        qCWarning(DDE_SHELL) << "Failed to start private session bus:" << busProcess->errorString();
        delete busProcess;
        return false;
    }

    if (!busProcess->waitForReadyRead(2000)) {
        qCWarning(DDE_SHELL) << "Private session bus did not print address in time";
        busProcess->terminate();
        busProcess->waitForFinished(1000);
        delete busProcess;
        return false;
    }

    m_securityQuestionBusAddress = QString::fromLocal8Bit(busProcess->readAllStandardOutput().split('\n').first()).trimmed();
    if (m_securityQuestionBusAddress.isEmpty()) {
        qCWarning(DDE_SHELL) << "Private session bus returned empty address";
        busProcess->terminate();
        busProcess->waitForFinished(1000);
        delete busProcess;
        return false;
    }

    m_securityQuestionBusProcess = busProcess;
    qCInfo(DDE_SHELL) << "Started private session bus for IME:" << m_securityQuestionBusAddress
                       << "original bus:" << QProcessEnvironment::systemEnvironment().value("DBUS_SESSION_BUS_ADDRESS");

    const QString fcitxBin = QStandardPaths::findExecutable(QStringLiteral("fcitx"));
    if (fcitxBin.isEmpty()) {
        qCWarning(DDE_SHELL) << "fcitx not found, cannot start fallback IME";
        stopSecurityQuestionIMEInfrastructure();
        return false;
    }

    auto *fcitxProcess = new QProcess(this);
    QProcessEnvironment fcitxEnv = QProcessEnvironment::systemEnvironment();
    fcitxEnv.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
    fcitxProcess->setProcessEnvironment(fcitxEnv);
    fcitxProcess->start(fcitxBin, QStringList() << QStringLiteral("-d"));
    if (!fcitxProcess->waitForStarted(2000)) {
        qCWarning(DDE_SHELL) << "Failed to start fallback fcitx:" << fcitxProcess->errorString();
        delete fcitxProcess;
        stopSecurityQuestionIMEInfrastructure();
        return false;
    }

    m_securityQuestionFcitxProcess = fcitxProcess;

    const int maxWaitMs = 5000;
    const int pollIntervalMs = 300;
    for (int waited = 0; waited < maxWaitMs; waited += pollIntervalMs) {
        QThread::msleep(pollIntervalMs);
        QProcess remoteCheck;
        QProcessEnvironment remoteEnv = QProcessEnvironment::systemEnvironment();
        remoteEnv.insert(QStringLiteral("DBUS_SESSION_BUS_ADDRESS"), m_securityQuestionBusAddress);
        remoteCheck.setProcessEnvironment(remoteEnv);
        remoteCheck.start(QStringLiteral("fcitx-remote"), QStringList());
        if (!remoteCheck.waitForStarted(1000) || !remoteCheck.waitForFinished(1000)) {
            continue;
        }
        const QString state = QString::fromLocal8Bit(remoteCheck.readAllStandardOutput().trimmed());
        if (!state.isEmpty()) {
            qCInfo(DDE_SHELL) << "Fallback fcitx is reachable after" << waited << "ms, state:" << state;
            return true;
        }
        if (waited == pollIntervalMs) {
            const QString errOutput = QString::fromLocal8Bit(remoteCheck.readAllStandardError().trimmed());
            if (!errOutput.isEmpty()) {
                qCWarning(DDE_SHELL) << "fcitx-remote stderr on first attempt:" << errOutput;
            }
        }
    }

    qCWarning(DDE_SHELL) << "Fallback fcitx did not become reachable within" << maxWaitMs << "ms";
    return true;
}

void SecurityQuestionManager::stopSecurityQuestionIMEInfrastructure()
{
    if (m_securityQuestionFcitxProcess) {
        if (m_securityQuestionFcitxProcess->state() != QProcess::NotRunning) {
            m_securityQuestionFcitxProcess->kill();
            m_securityQuestionFcitxProcess->waitForFinished(1000);
            qCInfo(DDE_SHELL) << "Stopped fallback fcitx";
        }
        m_securityQuestionFcitxProcess->deleteLater();
        m_securityQuestionFcitxProcess = nullptr;
    }

    if (m_securityQuestionBusProcess) {
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

    if (m_fcitxRemoteCheck) {
        m_fcitxRemoteCheck->kill();
        m_fcitxRemoteCheck->waitForFinished(500);
        m_fcitxRemoteCheck->deleteLater();
        m_fcitxRemoteCheck = nullptr;
    }

    m_securityQuestionBusAddress.clear();
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
