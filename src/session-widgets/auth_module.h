// SPDX-FileCopyrightText: 2021 - 2022 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef AUTHMODULE_H
#define AUTHMODULE_H

#include "authcommon.h"
#include "constants.h"
#include "reset_password_helper.h"

#include <DLabel>
#include <DPushButton>
#include <DIconButton>
#include <DFloatingMessage>

#include <QWidget>
#include <QDebug>
#include <QPointer>

#define CAPS_LOCK QStringLiteral(":/misc/images/caps_lock.svg")
#define LOGIN_CHECK QStringLiteral(":/misc/images/login_check.svg")
#define LOGIN_LOCK QStringLiteral(":/misc/images/login_lock.svg")
#define LOGIN_WAIT QStringLiteral(":/misc/images/login_wait.svg")
#define LOGIN_RETRY QStringLiteral(":/misc/images/retry16.svg")
#define LOGIN_SPINNER QStringLiteral(":/misc/images/login_spinner.svg")
#define PASSWORD_HINT QStringLiteral(":/misc/images/password_hint.svg")
#define AUTH_LOCK QStringLiteral(":/misc/images/unlock/unlock_1.svg")
#define UnionID_Auth QStringLiteral(":/misc/images/auth/UnionID.svg")
#define ResetPassword_Exe_Path QStringLiteral("/usr/lib/dde-control-center/reset-password-dialog")
#define DEEPIN_DEEPINID_DAEMON_PATH QStringLiteral("/usr/lib/deepin-deepinid-daemon/deepin-deepinid-daemon")

DWIDGET_USE_NAMESPACE
using namespace DDESESSIONCC;

struct LimitsInfo {
    bool locked = false;        // 认证锁定状态 --- true: 锁定  false: 解锁
    uint maxTries;      // 最大重试次数
    uint numFailures;   // 失败次数，一直累加
    uint unlockSecs;    // 本次锁定总解锁时间（秒），不会随着时间推移减少
    QString unlockTime; // 解锁时间（本地时间）

    void operator=(const LimitsInfo &info);

#ifdef QT_DEBUG
    friend QDebug operator<<(QDebug out, const LimitsInfo& info)
    {
        out << "locked:" << info.locked
            << ", maxTried:" << info.maxTries
            << ", numFailures:" << info.numFailures
            << ", unlockSecs:" << info.unlockSecs
            << ", unlockTime:" << info.unlockTime;
        return out;
    }
#endif
};

class AuthModule : public QWidget
{
    Q_OBJECT
public:
    enum TextType {
        AlertText,
        InputText,
        PlaceHolderText
    };
    Q_ENUM(TextType)

    explicit AuthModule(const AuthCommon::AuthType type, QWidget *parent = nullptr);
    ~AuthModule() override;

    inline AuthCommon::AuthType authType() const { return m_type; }
    inline AuthCommon::AuthState authState() const { return m_state; }

    virtual void setAnimationState(const bool start);
    virtual void setAuthState(const AuthCommon::AuthState state, const QString &result);
    void setAuthStateStyle(const QString &path);
    virtual void setLimitsInfo(const LimitsInfo &info);
    void setAuthStatueVisible(bool visible);
    void setAuthStateLabel(DLabel *label);
    virtual void setAuthFactorType(AuthFactorType authFactorType);
    inline bool isMFA() const { return m_authFactorType == DDESESSIONCC::MultiAuthFactor; }
    bool isLocked() const;

    // 重置密码相关
    void connectResetPasswordHelper(ResetPasswordHelper *helper);
    void onResetPasswordHelperRequestSecurityQuestionReset();
    void onResetPasswordHelperRequestDialogStateChanged(bool visible);
    void onResetPasswordHelperAvailableMethodsChanged(int methods);
    virtual void resetPasswordMessageVisibleChanged(bool visible) { Q_UNUSED(visible); }
    virtual void resetPasswordCloseMessage();
    virtual void resetPasswordShowMessage(int methods);

    // 重置密码公共方法（派生类可继承使用）
    virtual void showResetPasswordMessage();
    virtual void closeResetPasswordMessage();
    virtual void updateResetPasswordUI();
    void clearResetPasswordCache();
    void requestRefreshResetPasswordCache();
    virtual void setCurrentUid(uid_t uid);
    virtual void setResetPasswordMessageVisible(bool isVisible);

    // 内部虚方法（子类可覆盖处理差异化行为）
    virtual void onResetPasswordMessageCloseButtonClicked();

    // 子类可覆盖的虚方法（由 showResetPasswordMessage 调用查找父窗口）
    // 默认实现：向上查找两级父窗口，子类（如 AuthPassword/AuthSingle）可覆盖
    virtual QWidget *findResetPasswordCenterFrame();

signals:
    void activeAuth(const AuthCommon::AuthType);
    void authFinished(const AuthCommon::AuthState);
    void requestAuthenticate();
    void unlockTimeChanged();
    void requestSecurityQuestionReset();
    void requestResetPasswordDialogStateChanged(bool visible);

protected:
    void initConnections();
    virtual void doAnimation() { }
    virtual void updateUnlockPrompt();
    void updateUnlockTime();
    void updateIntegerMinutes();

protected:
    int m_inputType;          // 认证信息输入设备类型
    AuthCommon::AuthState m_state;  // 认证状态
    AuthCommon::AuthType m_type;   // 认证类型
    bool m_showPrompt;        // 是否显示默认提示文案
    uint m_integerMinutes;    // 认证剩余解锁的整数分钟
    LimitsInfo *m_limitsInfo; // 认证限制相关信息
    QPointer<DLabel> m_authStateLabel; // 认证状态图标
    QTimer *m_aniTimer;       // 动画执行定时器
    QTimer *m_unlockTimer;    // 认证解锁定时器
    bool m_isAuthing;         // 是否正在验证
    AuthFactorType m_authFactorType;    // 验证因子类型
    bool m_showAuthState;     // 是否显示验证状态控件
    bool m_resetPasswordMessageVisible = false;

    // 重置密码浮窗相关
    QPointer<DFloatingMessage> m_resetPasswordFloatingMessage;
    QPointer<DPushButton> m_resetPasswordPushButton;
    DIconButton *m_iconButton = nullptr;
    ResetPasswordHelper *m_resetPasswordHelper = nullptr;
    uid_t m_currentUid = 0;
    bool m_resetDialogShow = false;
};

#endif // AUTHMODULE_H
