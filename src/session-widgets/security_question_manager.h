// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SECURITYQUESTIONMANAGER_H
#define SECURITYQUESTIONMANAGER_H

#include <QObject>
#include <QProcess>
#include <QTimer>

#include <sys/types.h>

class SessionBaseModel;

class SecurityQuestionManager : public QObject
{
    Q_OBJECT
public:
    explicit SecurityQuestionManager(SessionBaseModel *model, QObject *parent = nullptr);
    ~SecurityQuestionManager();

    bool hasResetPasswordDialog() const { return m_hasResetPasswordDialog; }
    bool isFlowInProgress() const { return m_flowInProgress; }
    void handleRequestReset(uid_t uid);
    void startSecurityQuestionFlow(const QString &payloadData);
    void setDialogState(bool visible);
    void cleanup();

signals:
    void resetPasswordDialogStateChanged(bool visible);
    void requestTryGrabKeyboard(bool exitIfFailed);
    void resetPasswordComplete(bool passwordChanged);

private:
    QString securityQuestionHelperExecutable() const;
    bool startSecurityQuestionHelper(const QString &payload);
    void cleanupSecurityQuestionHelper();
    bool startSecurityQuestionIMEInfrastructure();
    void stopSecurityQuestionIMEInfrastructure();
    void setFcitxSocketAcl(const QString &user, quint32 uid, bool enable);
    void onHelperFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onHelperError(QProcess::ProcessError error);
    void resetDialogState();
    void startImeAsync();
    void continueImeSetup();
    void startHelperAfterIme();
    void onImeTimeout();

    SessionBaseModel *m_model;
    QProcess *m_securityQuestionHelperProcess = nullptr;
    QProcess *m_securityQuestionBusProcess = nullptr;
    QProcess *m_securityQuestionFcitxProcess = nullptr;
    QProcess *m_fcitxRemoteCheck = nullptr;
    QString m_securityQuestionBusAddress;
    QString m_pendingPayload;
    QTimer *m_imePollTimer = nullptr;
    int m_imeStage = 0;
    int m_imePollCount = 0;
    bool m_securityQuestionFcitxAclSet = false;
    quint32 m_securityQuestionFcitxAclUid = 0;
    bool m_hasResetPasswordDialog = false;
    bool m_flowInProgress = false;
};

#endif // SECURITYQUESTIONMANAGER_H
