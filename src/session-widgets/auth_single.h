// SPDX-FileCopyrightText: 2021 - 2022 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef AUTHSINGLE_H
#define AUTHSINGLE_H

#include "auth_module.h"

#include <DIconButton>
#include <DPushButton>
#include <DSuggestButton>

class DLineEditEx;
class AuthSingle : public AuthModule
{
    Q_OBJECT
public:
    explicit AuthSingle(QWidget *parent = nullptr);
    virtual ~AuthSingle() override;

    void reset();
    QString lineEditText() const;

    inline bool passwordLineEditEnabled() const { return m_passwordLineEditEnabled; }
    void setPasswordLineEditEnabled(const bool enable);

    void setAnimationState(const bool start) override;
    void setAuthState(const AuthCommon::AuthState state, const QString &result) override;
    void setCapsLockVisible(const bool on);
    void setKeyboardButtonInfo(const QString &text);
    void setKeyboardButtonVisible(const bool visible);
    void setLimitsInfo(const LimitsInfo &info) override;
    void setLineEditEnabled(const bool enable);
    void setLineEditInfo(const QString &text, const TextType type);
    void setPasswordHint(const QString &hint);
    void setCurrentUid(uid_t uid);

signals:
    void focusChanged(const bool);
    void lineEditTextChanged(const QString &); // 数据同步
    void requestShowKeyboardList();            // 显示键盘布局列表
    void resetPasswordMessageVisibleChanged(const bool isVisible);
public slots:
    void setResetPasswordMessageVisible(const bool isVisible);
protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void initUI();
    void initConnections();

    void updateUnlockPrompt() override;
    void showPasswordHint();
    void setPasswordHintBtnVisible(const bool isVisible);
    void updatePasswordTextMargins();

private:
    bool m_passwordLineEditEnabled;
    DLabel *m_capsLock;             // 大小写状态
    DLineEditEx *m_lineEdit;        // 输入框
    DPushButton *m_keyboardBtn;     // 键盘布局按钮
    DIconButton *m_passwordHintBtn; // 密码提示按钮
    QString m_passwordHint;         // 密码提示
};

#endif // AUTHSINGLE_H
