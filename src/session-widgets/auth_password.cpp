// SPDX-FileCopyrightText: 2021 - 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "auth_password.h"
#include "plugin_manager.h"

#include "authcommon.h"
#include "dlineeditex.h"
#include "dstyle.h"
#include "dbusconstant.h"

#include <DHiDPIHelper>
#include <DLabel>
#include <DPaletteHelper>
#include <DDialogCloseButton>
#include <DFontSizeManager>

#include <QKeyEvent>
#include <QTimer>
#include <QVBoxLayout>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QWindow>
#include <QValidator>

#include <DConfig>
#ifndef ENABLE_DSS_SNIPE
#include <QRegExp>
#include <com_deepin_daemon_accounts_user.h>
#else
#include "userinterface.h"
#endif

const QString PASSWORD_HIDE = QStringLiteral(":/misc/images/password-hide.svg");
const QString PASSWORD_SHOWN = QStringLiteral(":/misc/images/password-shown.svg");
const QString DConfig_LongPressDisplayPassword = "longPressDisplayPassword";

using namespace AuthCommon;
using DSS_PLUGIN_TYPE = dss::module::BaseModuleInterface::ModuleType;

AuthPassword::AuthPassword(QWidget *parent)
    : AuthModule(AT_Password, parent)
    , m_capsLock(new DLabel(this))
    , m_lineEdit(new DLineEditEx(this))
    , m_passwordShowBtn(new DIconButton(this))
    , m_passwordHintBtn(new DIconButton(this))
    , m_passwordTipsWidget(new PasswordErrorTipsWidget(this))
    , m_passwordHintWidget(nullptr)
    , m_isPasswdAuthWidgetReplaced(false)
    , m_assistLoginWidget(nullptr)
    , m_authenticationDconfig(DConfig::create("org.deepin.dde.authentication", "org.deepin.dde.authentication.errorecho", QString(), this))
    , m_canShowPasswordErrorTips(false)
{
    qRegisterMetaType<LoginPlugin::PluginConfig>("LoginPlugin::PluginConfig");

    setMaximumSize(500,200);
    setObjectName(QStringLiteral("AuthPassword"));
    setAccessibleName(QStringLiteral("AuthPassword"));

    initUI();
    initConnections();

    m_resetPasswordHelper = new ResetPasswordHelper(this);
    connectResetPasswordHelper(m_resetPasswordHelper);

    m_lineEdit->installEventFilter(this);
    m_lineEdit->setCopyEnabled(false);
    m_lineEdit->setCutEnabled(false);
    setFocusProxy(m_lineEdit);
}

AuthPassword::~AuthPassword()
{
    // QWidget析构时会clearFocus, focusChanged会被触发，且槽函数操作了成员变量会导致崩溃，在这里提前断开连接
    m_lineEdit->disconnect(this);
}

/**
 * @brief 初始化界面
 */
void AuthPassword::initUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(10);

    m_lineEdit->setClearButtonEnabled(false);
    m_lineEdit->setEchoMode(QLineEdit::Password);
    m_lineEdit->setSecureInputEnabled(true);
    m_lineEdit->setContextMenuPolicy(Qt::NoContextMenu);
    m_lineEdit->setFocusPolicy(Qt::StrongFocus);
    m_lineEdit->lineEdit()->setAlignment(Qt::AlignCenter);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    m_lineEdit->lineEdit()->setValidator(new QRegularExpressionValidator(QRegularExpression("^[ -~]+$")));
#else
    m_lineEdit->lineEdit()->setValidator(new QRegExpValidator(QRegExp("^[ -~]+$")));
#endif
    DFontSizeManager::instance()->bind(m_lineEdit, DFontSizeManager::T6);

    setLineEditInfo(tr("Password"), PlaceHolderText);

    QHBoxLayout *passwordLayout = new QHBoxLayout(m_lineEdit->lineEdit());
    passwordLayout->setContentsMargins(10, 0, 10, 0);
    passwordLayout->setSpacing(5);
    /* 大小写状态 */
    QPixmap pixmap = DHiDPIHelper::loadNxPixmap(CAPS_LOCK);
    pixmap.setDevicePixelRatio(devicePixelRatioF());
    m_capsLock->setPixmap(pixmap);
    passwordLayout->addWidget(m_capsLock, 0, Qt::AlignLeft | Qt::AlignVCenter);
    /* 缩放因子 */
    passwordLayout->addStretch(1);

    /* 认证状态 */
    m_authStateLabel = new DLabel(this);
    m_authStateLabel->setVisible(false);
    setAuthStateStyle(LOGIN_WAIT);
    passwordLayout->addWidget(m_authStateLabel, 0, Qt::AlignRight | Qt::AlignVCenter);

    /*显示密码*/
    m_passwordShowBtn->setAccessibleName(QStringLiteral("PasswordShow"));
    m_passwordShowBtn->setContentsMargins(0, 0, 0, 0);
    m_passwordShowBtn->setFocusPolicy(Qt::NoFocus);
    m_passwordShowBtn->setCursor(Qt::ArrowCursor);
    m_passwordShowBtn->setFlat(true);
    m_passwordShowBtn->setIcon(QIcon(PASSWORD_SHOWN));
    m_passwordShowBtn->setIconSize(QSize(16, 16));
    m_passwordShowBtn->setVisible(true);
    passwordLayout->addWidget(m_passwordShowBtn, 0, Qt::AlignRight | Qt::AlignVCenter);

    /* 密码提示 */
    m_passwordHintBtn->setAccessibleName(QStringLiteral("PasswordHint"));
    m_passwordHintBtn->setContentsMargins(0, 0, 0, 0);
    m_passwordHintBtn->setFocusPolicy(Qt::NoFocus);
    m_passwordHintBtn->setCursor(Qt::ArrowCursor);
    m_passwordHintBtn->setFlat(true);
    m_passwordHintBtn->setIcon(QIcon(PASSWORD_HINT));
    m_passwordHintBtn->setIconSize(QSize(16, 16));
    m_passwordHintBtn->setVisible(false);
    passwordLayout->addWidget(m_passwordHintBtn, 0, Qt::AlignRight | Qt::AlignVCenter);
    mainLayout->addWidget(m_lineEdit);
    auto plugin = PluginManager::instance()->getAssistloginPlugin();

    if (plugin) {
        m_isPasswdAuthWidgetReplaced = true;
        m_assistLoginWidget = new AssistLoginWidget(this);
        m_assistLoginWidget->setModule(plugin);
        m_assistLoginWidget->initUI();
        mainLayout->addWidget(m_assistLoginWidget);
        m_lineEdit->hide();
    } else {
        m_lineEdit->show();
    }

    // 密码框下面增加一个认证界面
    auto extendPlugin = PluginManager::instance()->getFirstLoginPlugin(dss::module::BaseModuleInterface::PasswordExtendLoginType);
    if (extendPlugin) {
        m_assistLoginWidget = new AssistLoginWidget(this);
        m_assistLoginWidget->setModule(extendPlugin);
        m_assistLoginWidget->initUI();
        mainLayout->addWidget(m_assistLoginWidget);
    } else {
        qCDebug(DDE_SHELL) << "There's no password extend plugin";
    }
    updatePasswordTextMargins();
    m_passwordTipsWidget->hide();
}

/**
 * @brief 初始化信号连接
 */
void AuthPassword::initConnections()
{
    AuthModule::initConnections();

    auto blockEditSig = [this]() -> bool {
        return m_assistLoginWidget
               && m_assistLoginWidget->isVisible()
               && DSS_PLUGIN_TYPE::PasswordExtendLoginType == m_assistLoginWidget->pluginType()
               && !m_assistLoginWidget->readyToAuth();
    };
    /* 密码提示 */
    connect(m_passwordHintBtn, &DIconButton::clicked, this, &AuthPassword::showPasswordHint);
    /* 密码输入框 */
    connect(m_lineEdit, &DLineEditEx::focusChanged, this, [this, blockEditSig](const bool focus) {
        if (!focus)
            m_lineEdit->setAlert(false);
        m_authStateLabel->setVisible(!focus && m_showAuthState);
        updatePasswordTextMargins();
        emit focusChanged(focus);
        if (focus && !blockEditSig()) {
            emit lineEditTextChanged(m_lineEdit->text());
        }

        if (focus) {
            QString kbLayout = getCurrentKBLayout();
            if (!kbLayout.isEmpty() && !kbLayout.toLower().startsWith("us")) {
                m_originalKBLayout = kbLayout;
                qCInfo(DDE_SHELL) << "Original keyboard layout:" << m_originalKBLayout;
                // 如果键盘布局有特殊设置，则切换到英文键盘布局，认证成功后恢复
                setKBLayout("us");
            }
        } else {
            if (!m_originalKBLayout.isEmpty()) {
                // 切换回原来的键盘布局
                setKBLayout(m_originalKBLayout);
                m_originalKBLayout.clear();
            }
        }
    });

    connect(this, &AuthPassword::authFinished, this, [this](const AuthState state) {
        if (state == AS_Success) {
            if (!m_originalKBLayout.isEmpty()) {
                // 切换回原来的键盘布局
                setKBLayout(m_originalKBLayout);
                m_originalKBLayout.clear();
            }
        }
    });

    connect(m_lineEdit, &DLineEditEx::textChanged, this, [this, blockEditSig](const QString &text) {
        m_lineEdit->hideAlertMessage();
        hidePasswordHintWidget();
        m_lineEdit->setAlert(false);
        updatePasswordTextMargins();
        if (canShowPasswrodErrorTip() && isShowPasswrodErrorTip()) {
            m_passwordTipsWidget->reset();
            m_passwordTipsWidget->setErrDetailVisible(false);
            m_passwordTipsWidget->setVisible(false);
            m_passwordTipsWidget->adjustSize();
            emit passwordErrorTipsClearChanged(true);
        }
        if (!blockEditSig())
            emit lineEditTextChanged(text);
    });
    connect(m_lineEdit, &DLineEditEx::returnPressed, this, [this, blockEditSig] {
        if (!m_lineEdit->lineEdit()->isReadOnly()) { // 避免用户在验证的时候反复点击
            if (!blockEditSig()) {
                emit requestAuthenticate();
            } else {
                setFocusProxy(m_assistLoginWidget);
                m_assistLoginWidget->setFocus();
            }
        }
    });

    if (DConfigHelper::instance()->getConfig(DConfig_LongPressDisplayPassword, true).toBool()) {
        connect(m_passwordShowBtn, &DSuggestButton::pressed, this, [this] {
            m_passwordShowBtn->setIcon(QIcon(PASSWORD_HIDE));
            if (m_lineEdit) {
                m_lineEdit->setEchoMode(QLineEdit::Normal);
            }
        });

        connect(m_passwordShowBtn, &DSuggestButton::released, this, [this] {
            m_passwordShowBtn->setIcon(QIcon(PASSWORD_SHOWN));
            if (m_lineEdit) {
                m_lineEdit->setEchoMode(QLineEdit::Password);
            }
        });
    } else {
        connect(m_passwordShowBtn, &DSuggestButton::clicked, this, [this] {
            if (m_lineEdit->echoMode() == QLineEdit::EchoMode::Password) {
                m_passwordShowBtn->setIcon(QIcon(PASSWORD_HIDE));
                m_lineEdit->lineEdit()->setEchoMode(QLineEdit::Normal);
                updatePasswordTextMargins();
            } else {
                m_passwordShowBtn->setIcon(QIcon(PASSWORD_SHOWN));
                m_lineEdit->lineEdit()->setEchoMode(QLineEdit::Password);
                updatePasswordTextMargins();
            }
        });
    }

    if (m_assistLoginWidget && m_isPasswdAuthWidgetReplaced) {
        connect(m_assistLoginWidget, &AssistLoginWidget::requestPluginConfigChanged, this, [this](const LoginPlugin::PluginConfig pluginConfig) {
            Q_EMIT requestPluginConfigChanged(pluginConfig);
        });
        connect(m_assistLoginWidget, &AssistLoginWidget::requestHidePlugin, this, [=] {
            hidePlugin();
        });
        connect(m_assistLoginWidget, &AssistLoginWidget::requestSendToken, this, &AuthPassword::requestPluginAuthToken);
    }

    if (m_assistLoginWidget) {
        connect(m_assistLoginWidget, &AssistLoginWidget::requestSendExtraInfo, this, [this](const QString &info) {
            if (!m_lineEdit->text().isEmpty()) {
                Q_EMIT requestAuthenticate();
                return;
            }

            // 焦点切换到密码输入框
            m_lineEdit->setFocus();
            setFocusProxy(m_lineEdit);
        });
        connect(m_assistLoginWidget, &AssistLoginWidget::readyToAuthChanged, this, &AuthPassword::onReadyToAuthChanged);
    }

    if (m_authenticationDconfig) {
        auto updateCanShow = [this] {
            m_canShowPasswordErrorTips = m_authenticationDconfig->value("PasswordErrorEcho", false).toBool();
        };

        connect(m_authenticationDconfig, &DConfig::valueChanged, this, updateCanShow);

        updateCanShow();
    }
}

/**
 * @brief AuthPassword::reset
 */
void AuthPassword::reset()
{
    m_lineEdit->setText(QString());
    m_lineEdit->setAlert(false);
    m_lineEdit->hideAlertMessage();
    setFocusProxy(m_lineEdit);
    m_lineEdit->setEchoMode(QLineEdit::Password);
    m_passwordShowBtn->setIcon(QIcon(PASSWORD_SHOWN));
    hidePasswordHintWidget();
    setLineEditEnabled(true);
    setLineEditInfo(tr("Password"), PlaceHolderText);
    if (m_passwordTipsWidget && canShowPasswrodErrorTip()) {
        m_passwordTipsWidget->reset();
        m_passwordTipsWidget->setErrDetailVisible(false);
        m_passwordTipsWidget->setVisible(false);
        m_passwordTipsWidget->adjustSize();
        emit passwordErrorTipsClearChanged(true);
    }

    closeResetPasswordMessage();
}

/**
 * @brief 设置认证状态
 *
 * @param state
 * @param result
 */
void AuthPassword::setAuthState(const AuthState state, const QString &result)
{
    m_state = state;
    switch (state) {
    case AS_Success:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_CHECK);
        m_lineEdit->setAlert(false);
        m_lineEdit->setText(QString());
        setLineEditEnabled(false);
        setLineEditInfo(tr("Verification successful"), PlaceHolderText);
        m_showPrompt = true;
        m_lineEdit->hideAlertMessage();
        hidePasswordHintWidget();
        m_resetDialogShow = false;
        emit authFinished(state);
        emit requestChangeFocus();
        if (m_assistLoginWidget) {
            m_assistLoginWidget->resetAuth();
            if (isPasswdAuthWidgetReplaced()) {
                hidePlugin();
            }
        }
        break;
    case AS_Failure: {
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        m_lineEdit->lineEdit()->selectAll();
        setLineEditEnabled(true);
        const int leftTimes = static_cast<int>(m_limitsInfo->maxTries - m_limitsInfo->numFailures);
        if (leftTimes > 1) {
            setLineEditInfo(tr("Verification failed, %n chances left", "", leftTimes), PlaceHolderText);
        } else if (leftTimes == 1) {
            setLineEditInfo(tr("Verification failed, only one chance left"), PlaceHolderText);
        }
        if (canShowPasswrodErrorTip()) {
            showErrorTip(tr("Wrong Password"));
        } else if (!m_limitsInfo->locked) {
            setLineEditInfo(tr("Wrong Password"), AlertText);
        }

        m_showPrompt = false;
        emit authFinished(state);

        if (isPasswdAuthWidgetReplaced()) {
            hidePlugin();
        }
        break;
    }
    case AS_Cancel:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        m_showPrompt = true;
        break;
    case AS_Timeout:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditInfo(result, AlertText);
        break;
    case AS_Error:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditInfo(result, AlertText);
        break;
    case AS_Verify:
        setAnimationState(true);
        setAuthStateStyle(LOGIN_SPINNER);
        break;
    case AS_Exception:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditInfo(result, AlertText);
        break;
    case AS_Prompt:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditEnabled(true);
        if (m_showPrompt) {
            setLineEditInfo(tr("Password"), PlaceHolderText);
        }
        break;
    case AS_Started:
        break;
    case AS_Ended:
        break;
    case AS_Locked:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_LOCK);
        setLineEditEnabled(false);
        m_lineEdit->setAlert(false);
        m_lineEdit->hideAlertMessage();
        if (m_integerMinutes == 1) {
            setLineEditInfo(tr("Please try again 1 minute later"), PlaceHolderText);
        } else {
            setLineEditInfo(tr("Please try again %n minutes later", "", static_cast<int>(m_integerMinutes)), PlaceHolderText);
        }
        m_showPrompt = false;
        m_passwordHintBtn->hide();
        break;
    case AS_Recover:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        break;
    case AS_Unlocked:
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditEnabled(true);
        m_showPrompt = true;
        break;
    case AS_VerifyCode:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditEnabled(true);
        break;
    default:
        setAnimationState(false);
        setAuthStateStyle(LOGIN_WAIT);
        setLineEditEnabled(true);
        setLineEditInfo(result, AlertText);
        qCWarning(DDE_SHELL) << "Error! The state of Password Auth is wrong, state: " << state << ", result: " << result;
        break;
    }
    if (m_assistLoginWidget) {
        m_assistLoginWidget->setAuthState(state, result);
    }
    update();
}

/**
 * @brief 设置认证动画状态
 *
 * @param start
 */
void AuthPassword::setAnimationState(const bool start)
{
    start ? m_lineEdit->startAnimation() : m_lineEdit->stopAnimation();
}

/**
 * @brief 设置大小写图标状态
 *
 * @param on
 */
void AuthPassword::setCapsLockVisible(const bool on)
{
    m_capsLock->setVisible(on);
    updatePasswordTextMargins();
}

/**
 * @brief 更新认证受限信息
 *
 * @param info
 */
void AuthPassword::setLimitsInfo(const LimitsInfo &info)
{
    const bool lockStateChanged = (info.locked != m_limitsInfo->locked);
    AuthModule::setLimitsInfo(info);
    // 如果lock状态发生变化且当前状态为非lock更新编辑框文案
    if (lockStateChanged && !info.locked)
        updateUnlockPrompt();

    m_passwordHintBtn->setVisible(info.numFailures > 0 && !m_passwordHint.isEmpty());
    updatePasswordTextMargins();
    if (m_limitsInfo->numFailures >= 3) {
        if (m_limitsInfo->locked) {
            setAuthState(AS_Locked, "Locked");
        }

        if (this->isVisible() && m_resetPasswordHelper->isShowResetPasswordMessage()) {
            qCDebug(DDE_SHELL) << "Begin reset passoword";
            setResetPasswordMessageVisible(true);
            updateResetPasswordUI();
        }
    } else {
        setResetPasswordMessageVisible(false);
        updateResetPasswordUI();
    }

    if (lockStateChanged)
        emit notifyLockedStateChanged(m_limitsInfo->locked);
}

/**
 * @brief 设置输入框中的文案
 *
 * @param text
 * @param type
 */
void AuthPassword::setLineEditInfo(const QString &text, const TextType type)
{
    switch (type) {
    case AlertText:
        showAlertMessage(text);
        m_lineEdit->setAlert(true);
        if (canShowPasswrodErrorTip()) {
            m_passwordTipsWidget->addErrorDetailMsg(text);
        } else {
            m_lineEdit->showAlertMessage(text, this, 5000);
            m_lineEdit->setAlert(true);
        }
        break;
    case InputText: {
        const int cursorPos = m_lineEdit->lineEdit()->cursorPosition();
        m_lineEdit->setText(text);
        m_lineEdit->lineEdit()->setCursorPosition(cursorPos);
        break;
    }
    case PlaceHolderText:
        m_lineEdit->setPlaceholderText(text);
        break;
    }
}

/**
 * @brief 密码提示
 * @param hint
 */
void AuthPassword::setPasswordHint(const QString &hint)
{
    if (hint == m_passwordHint) {
        return;
    }
    m_passwordHint = hint;
}

void AuthPassword::setCurrentUid(uid_t uid)
{
    if (m_currentUid != uid) {
        AuthModule::setCurrentUid(uid);
    }
}

/**
 * @brief 获取输入框中的文字
 *
 * @return QString
 */
QString AuthPassword::lineEditText() const
{
    return m_lineEdit->text();
}

/**
 * @brief 设置 LineEdit 是否可输入
 *
 * @param enable
 */
void AuthPassword::setLineEditEnabled(const bool enable)
{
    if (!m_passwordLineEditEnabled) {
        m_lineEdit->setFocusPolicy(Qt::NoFocus);
        m_lineEdit->clearFocus();
        m_lineEdit->lineEdit()->setReadOnly(true);
        m_lineEdit->lineEdit()->setEnabled(false);
    } else if (enable && !m_limitsInfo->locked) {
        m_lineEdit->setFocusPolicy(Qt::StrongFocus);
        m_lineEdit->setFocus();
        m_lineEdit->lineEdit()->setReadOnly(false);
        m_lineEdit->lineEdit()->setEnabled(true);
    } else {
        m_lineEdit->setFocusPolicy(Qt::NoFocus);
        m_lineEdit->clearFocus();
        m_lineEdit->lineEdit()->setReadOnly(true);
        m_lineEdit->lineEdit()->setEnabled(true);
    }
}

void AuthPassword::setPasswordLineEditEnabled(const bool enable)
{
    m_passwordLineEditEnabled = enable;
    setLineEditEnabled(enable);
}

/**
 * @brief 更新认证锁定时的文案
 */
void AuthPassword::updateUnlockPrompt()
{
    AuthModule::updateUnlockPrompt();
    if (m_integerMinutes == 1) {
        m_lineEdit->setText(QString());
        m_lineEdit->setPlaceholderText(tr("Please try again 1 minute later"));
    } else if (m_integerMinutes > 1) {
        m_lineEdit->setText(QString());
        m_lineEdit->setPlaceholderText(tr("Please try again %n minutes later", "", static_cast<int>(m_integerMinutes)));
    } else {
        setLineEditInfo(tr("Password"), PlaceHolderText);
        QTimer::singleShot(1000, this, [this] {
            emit activeAuth(m_type);
        });
        qCInfo(DDE_SHELL) << "Waiting authentication service...";
    }
    update();
}

/**
 * @brief 显示密码提示
 */
void AuthPassword::showPasswordHint()
{
    // FIXME dtk如果后期提供接口设置alert的调色板，那么直接设置即可
    // 在这里将调色板的TextWarning改成黑色，让DAlertControl继承父类调色板，从而能显示黑色的文字
    DPalette palette = DPaletteHelper::instance()->palette(this->topLevelWidget());
    palette.setColor(DPalette::TextWarning, Qt::black);
    DPaletteHelper::instance()->setPalette(this->topLevelWidget(), palette);

    // 每次显示都需要重新生成对象，因为无法修改其内部私有对象的调色板，只能在创建对象的时候从父对象继承
    if (!m_passwordHintWidget) {
        m_passwordHintWidget = new DAlertControl(m_lineEdit->lineEdit());
        QTimer::singleShot(5000, this, &AuthPassword::hidePasswordHintWidget);
    }
    m_passwordHintWidget->showAlertMessage(m_passwordHint, m_lineEdit->lineEdit(), 5000);
    m_lineEdit->hideAlertMessage();
}

/**
 * @brief 设置密码提示按钮的可见性
 * @param visible
 */
void AuthPassword::setPasswordHintBtnVisible(const bool isVisible)
{
    m_passwordHintBtn->setVisible(isVisible);
    updatePasswordTextMargins();
}

/**
 * @brief 设置重置密码消息框的显示状态数据
 * @param isVisible
 * @param fromResetDialog 是否通过重置对话框关闭
 */
void AuthPassword::setResetPasswordMessageVisible(const bool isVisible, bool fromResetDialog)
{
    qCDebug(DDE_SHELL) << "Set reset password message visible, incoming visible:" << isVisible
                       << " current visible:" << m_resetPasswordMessageVisible
                       << " fromResetDialog " << fromResetDialog;
    if (isVisible && fromResetDialog) {
        m_resetDialogShow = false;
    }

    if (m_resetPasswordMessageVisible == isVisible)
        return;

    // 如果设置为显示重置按钮，失败次数>=3次就显示重置密码 1060-24505
    if (isVisible && ((m_limitsInfo && m_limitsInfo->numFailures < 3) || m_resetDialogShow)) {
        return;
    }

    m_resetPasswordMessageVisible = isVisible;
    emit resetPasswordMessageVisibleChanged(m_resetPasswordMessageVisible);
}

void AuthPassword::onResetPasswordMessageCloseButtonClicked()
{
    m_resetPasswordMessageVisible = false;
    emit resetPasswordMessageVisibleChanged(false);
    // 重置密码后，输入框重新获取焦点
    if (m_lineEdit)
        m_lineEdit->setFocus();
}

bool AuthPassword::eventFilter(QObject *watched, QEvent *event)
{
    if (qobject_cast<DLineEditEx *>(watched) == m_lineEdit && event->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(event);
        if (keyEvent->matches(QKeySequence::Cut)
            || keyEvent->matches(QKeySequence::Copy)
            || keyEvent->matches(QKeySequence::Paste)) {
            return true;
        }
    }

    if (watched == m_iconButton && event->type() == QEvent::Paint) {
        QPainter painter(m_iconButton);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.setRenderHint(QPainter::SmoothPixmapTransform, true);

        if (!m_iconButton->icon().isNull()) {
            QRect iconRect(0, 0, 20, 20);
            iconRect.moveCenter(m_iconButton->rect().center());
            m_iconButton->icon().paint(&painter, iconRect);
        }

        return true;
    }

    return false;
}

void AuthPassword::hideEvent(QHideEvent *event)
{
    m_lineEdit->setAlert(false);
    m_lineEdit->hideAlertMessage();
    hidePasswordHintWidget();
    setLineEditInfo(tr("Password"), PlaceHolderText);
    closeResetPasswordMessage();
    m_passwordTipsWidget->hide();
    AuthModule::hideEvent(event);
}

void AuthPassword::showEvent(QShowEvent *event)
{
    // 锁屏显示时请求刷新缓存，确保使用最新数据
    m_resetPasswordHelper->requestRefresh();

    m_passwordHintBtn->setVisible(m_limitsInfo->numFailures > 0 && !m_passwordHint.isEmpty());
    updatePasswordTextMargins();
    if (m_limitsInfo->numFailures >= 3) {
        if (m_limitsInfo->locked) {
            setAuthState(AS_Locked, "Locked");
        }

        if (m_resetPasswordHelper->isShowResetPasswordMessage()) {
            qCDebug(DDE_SHELL) << "Begin reset passoword";
            setResetPasswordMessageVisible(true);
            updateResetPasswordUI();
        }
    } else {
        setResetPasswordMessageVisible(false);
        updateResetPasswordUI();
    }

    if (canShowPasswrodErrorTip()) {
        QTimer::singleShot(0, this, [ = ] {
            updatePasswrodErrorTipUi();
        });
    }

    AuthModule::showEvent(event);
}

void AuthPassword::setAuthStatueVisible(bool visible)
{
    m_showAuthState = visible;
    m_authStateLabel->setVisible(visible && !hasFocus());
    updatePasswordTextMargins();
}

void AuthPassword::showAlertMessage(const QString &text)
{
    hidePasswordHintWidget();
    m_lineEdit->showAlertMessage(text, this, 5000);
}

void AuthPassword::hidePasswordHintWidget()
{
    if (m_passwordHintWidget) {
        m_passwordHintWidget->deleteLater();
        m_passwordHintWidget = nullptr;
    }

    // 恢复调色板
    DPaletteHelper::instance()->resetPalette(this->topLevelWidget());
}

void AuthPassword::updatePasswordTextMargins()
{
    QMargins textMargins = m_lineEdit->lineEdit()->textMargins();
    // 右边控件宽度+控件间距
    const int rightWidth = (m_passwordShowBtn->isVisible() ? m_passwordShowBtn->width() + 5 : 0) + (m_authStateLabel->isVisible() ? m_authStateLabel->width() + 5 : 0) + (m_passwordHintBtn->isVisible() ? m_passwordHintBtn->width() + 5 : 0);
    // 左侧控件宽度
    const int leftWidth = (m_capsLock->isVisible() ? m_capsLock->width() + 5 : 0);
    textMargins.setRight(rightWidth);
#if QT_VERSION >= QT_VERSION_CHECK(6, 6, 0)
    const int displayTextWidth = m_lineEdit->lineEdit()->fontMetrics().horizontalAdvance(m_lineEdit->lineEdit()->displayText());
#else
    const int displayTextWidth = m_lineEdit->lineEdit()->fontMetrics().width(m_lineEdit->lineEdit()->displayText());
#endif
    // 计算当前文字长度+图标+间距所需长度 和 编辑框长度的差值，如果空间不足，则缩减左边的margin，但是不小于左侧控件的宽度
    const int diff = m_lineEdit->lineEdit()->width() - 10 /*borer padding等宽度*/ - (displayTextWidth + 15 /*content margin*/ + textMargins.right() * 2);
    textMargins.setLeft(qMax(leftWidth, rightWidth + (diff < 0 ? diff : 0)));
    if (textMargins == m_lineEdit->lineEdit()->textMargins()) {
        return;
    }

    m_lineEdit->lineEdit()->setTextMargins(textMargins);
}

void AuthPassword::updatePluginConfig()
{
    if (m_assistLoginWidget && m_isPasswdAuthWidgetReplaced) {
        m_assistLoginWidget->updateConfig();
    }
}

void AuthPassword::hidePlugin()
{
    if (m_assistLoginWidget == nullptr) {
        return;
    }
    m_isPasswdAuthWidgetReplaced = false;
    m_assistLoginWidget->hide();
    m_lineEdit->show();

    Q_EMIT requestHidePlugin();
}

void AuthPassword::startPluginAuth()
{
    if (m_assistLoginWidget) {
        m_assistLoginWidget->startAuth();
    }
}

bool AuthPassword::isShowPasswrodErrorTip()
{
    return m_passwordTipsWidget->isVisible();
}

void AuthPassword::showErrorTip(const QString &text)
{
    if (canShowPasswrodErrorTip()) {
        m_lineEdit->hideAlertMessage();
        m_lineEdit->setAlert(false);
        m_passwordTipsWidget->setErrorTips(text);
        m_passwordTipsWidget->setVisible(isVisible());
    } else {
        m_lineEdit->showAlertMessage(text, this, 5000);
        m_lineEdit->setAlert(true);
    }
}

void AuthPassword::clearPasswrodErrorTip(bool isClear)
{
    if (isClear) {
        m_passwordTipsWidget->reset();
    }
}

void AuthPassword::updatePasswrodErrorTipUi()
{
    m_passwordTipsWidget->setVisible(m_passwordTipsWidget->hasErrorTips());
    QRect rc =  m_lineEdit->geometry();

    QPoint pt(rc.x(), rc.y() + rc.height() +5);

    pt = m_lineEdit->mapToGlobal(pt);
    m_passwordTipsWidget->move(pt);
}

void AuthPassword::resizeEvent(QResizeEvent *event)
{
    qInfo() << Q_FUNC_INFO << event->size() << event->oldSize();
    if (canShowPasswrodErrorTip()) {
        QTimer::singleShot(0, this, [ = ] {
            updatePasswrodErrorTipUi();
        });
    }
    QWidget::resizeEvent(event);
}

void AuthPassword::moveEvent(QMoveEvent *event)
{
    qInfo() << Q_FUNC_INFO << event->pos() << event->oldPos();
    if (canShowPasswrodErrorTip()) {
        QTimer::singleShot(0, this, [ = ] {
            updatePasswrodErrorTipUi();
        });
    }
    QWidget::moveEvent(event);
}

void AuthPassword::onReadyToAuthChanged(bool ready)
{
    ready ? emit lineEditTextChanged(m_lineEdit->text()) : emit lineEditTextChanged("");
}


QString AuthPassword::getCurrentKBLayout() const
{
    QProcess p;
    p.start("/usr/bin/setxkbmap", {"-query"});
    p.waitForFinished();

    const QString output = QString::fromUtf8(p.readAllStandardOutput());
    for (const QString &line : output.split('\n')) {
        if (line.startsWith("layout:")) {
            QString layout = line.section(':', 1).trimmed();
            return layout;
        }
    }

    return {};
}

void AuthPassword::setKBLayout(const QString &layout)
{
    qCDebug(DDE_SHELL) << "Set keyboard layout: " << layout;
    QProcess::execute("/usr/bin/setxkbmap", { layout});
}