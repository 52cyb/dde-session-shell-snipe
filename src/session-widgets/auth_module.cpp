// SPDX-FileCopyrightText: 2021 - 2022 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include "auth_module.h"
#include "dconfig_helper.h"

#include <DHiDPIHelper>
#include <DDialogCloseButton>
#include <DFloatingMessage>
#include <DPushButton>
#include <DMessageManager>
#include <DPaletteHelper>
#include <DPlatformWindowHandle>

#include <QDateTime>
#include <QTimer>
#include <QtMath>
#include <QMenu>

void LimitsInfo::operator=(const LimitsInfo &info)
{
    locked = info.locked;
    maxTries = info.maxTries;
    numFailures = info.numFailures;
    unlockSecs = info.unlockSecs;
    unlockTime = info.unlockTime;
}

AuthModule::AuthModule(const AuthCommon::AuthType type, QWidget *parent)
    : QWidget(parent)
    , m_inputType(AuthCommon::IT_Default)
    , m_state(AuthCommon::AS_None)
    , m_type(type)
    , m_showPrompt(true)
    , m_integerMinutes(0)
    , m_limitsInfo(new LimitsInfo())
    , m_aniTimer(new QTimer(this))
    , m_unlockTimer(new QTimer(this))
    , m_isAuthing(false)
    , m_authFactorType(DDESESSIONCC::SingleAuthFactor)
    , m_showAuthState(false)
{
    setMinimumHeight(37);

    m_limitsInfo->locked = false;
    m_limitsInfo->maxTries = 0;
    m_limitsInfo->numFailures = 0;
    m_limitsInfo->unlockSecs = 0;
    m_limitsInfo->unlockTime = QString("0001-01-01T00:00:00Z");

    m_unlockTimer->setSingleShot(false);
    m_unlockTimer->setInterval(1000);
}

AuthModule::~AuthModule()
{
    delete m_limitsInfo;
}

/**
 * @brief 初始化信号连接
 */
void AuthModule::initConnections()
{
    /* 认证解锁时间 */
    connect(m_unlockTimer, &QTimer::timeout, this, [this] {
        updateIntegerMinutes();
        if (m_integerMinutes == 0)
            m_unlockTimer->stop();
        updateUnlockPrompt();
    });
    /* 解锁动画 */
    connect(m_aniTimer, &QTimer::timeout, this, &AuthModule::doAnimation);
}

/**
 * @brief 设置认证动画状态，由派生类重载，自定义动画样式。
 *
 * @param start
 */
void AuthModule::setAnimationState(const bool start)
{
    Q_UNUSED(start)
}

/**
 * @brief 设置认证的状态，由派生类重载，自定义认证状态显示样式。
 *
 * @param state
 * @param result
 */
void AuthModule::setAuthState(const AuthCommon::AuthState state, const QString &result)
{
    Q_UNUSED(result)

    if (AuthCommon::AS_Started == state)
        m_isAuthing = true;
    else if (AuthCommon::AS_Ended == state)
        m_isAuthing = false;
}

/**
 * @brief 设置认证状态图标的样式
 *
 * @param path
 */
void AuthModule::setAuthStateStyle(const QString &path)
{
    if (!m_authStateLabel)
        return;

    QPixmap pixmap = DHiDPIHelper::loadNxPixmap(path);
    pixmap.setDevicePixelRatio(devicePixelRatioF());
    m_authStateLabel->setPixmap(pixmap);
}

/**
 * @brief 设置认证受限信息
 *
 * @param info
 */
void AuthModule::setLimitsInfo(const LimitsInfo &info)
{
    *m_limitsInfo = info;
    updateUnlockTime();
}

void AuthModule::setAuthStatueVisible(bool visible)
{
    if (m_authStateLabel) {
        m_authStateLabel->setVisible(visible);
    }
}

/**
 * @brief 更新认证剩余解锁时间提示
 */
void AuthModule::updateUnlockPrompt()
{
    qCInfo(DDE_SHELL) << "Update unlock prompt, type: " << m_type << ", which has " << m_integerMinutes << " minutes left to unlock.";
}

/**
 * @brief 更新认证锁定后的解锁时间
 */
void AuthModule::updateUnlockTime()
{
    if (QDateTime::fromString(m_limitsInfo->unlockTime, Qt::ISODateWithMs) <= QDateTime::currentDateTime()) {
        m_integerMinutes = 0;
        m_unlockTimer->stop();
        if (m_limitsInfo->locked)
            updateUnlockPrompt();
        return;
    }
    updateIntegerMinutes();
    updateUnlockPrompt();
    m_unlockTimer->start();
}

void AuthModule::updateIntegerMinutes()
{
    if (QDateTime::fromString(m_limitsInfo->unlockTime, Qt::ISODateWithMs) > QDateTime::currentDateTime()) {
        qreal intervalSeconds = QDateTime::fromString(m_limitsInfo->unlockTime, Qt::ISODateWithMs).toLocalTime().toSecsSinceEpoch()  - QDateTime::currentDateTimeUtc().toSecsSinceEpoch();
        m_integerMinutes = static_cast<uint>(qCeil(intervalSeconds / 60));
    } else {
        m_integerMinutes = 0;
    }
}

void AuthModule::setAuthStateLabel(DLabel *label)
{
    if (!label)
        return;

    if (m_authStateLabel) {
        delete m_authStateLabel;
        m_authStateLabel = nullptr;
    }

    /* 认证状态 */
    m_authStateLabel = label;
    setAuthStateStyle(AUTH_LOCK);
}

void AuthModule::setAuthFactorType(AuthFactorType authFactorType)
{
    m_authFactorType = authFactorType;
}

bool AuthModule::isLocked() const
{
    return m_limitsInfo->locked;
}

void AuthModule::connectResetPasswordHelper(ResetPasswordHelper *helper)
{
    connect(helper, &ResetPasswordHelper::requestSecurityQuestionReset,
            this, &AuthModule::onResetPasswordHelperRequestSecurityQuestionReset);
    connect(helper, &ResetPasswordHelper::requestResetPasswordDialogStateChanged,
            this, &AuthModule::onResetPasswordHelperRequestDialogStateChanged);
    connect(helper, &ResetPasswordHelper::availableMethodsChanged,
            this, &AuthModule::onResetPasswordHelperAvailableMethodsChanged);
}

void AuthModule::onResetPasswordHelperRequestSecurityQuestionReset()
{
    Q_EMIT requestSecurityQuestionReset();
}

void AuthModule::onResetPasswordHelperRequestDialogStateChanged(bool visible)
{
    m_resetPasswordMessageVisible = visible;
    Q_EMIT requestResetPasswordDialogStateChanged(visible);
}

void AuthModule::onResetPasswordHelperAvailableMethodsChanged(int methods)
{
    // 延迟执行，避免信号同步传递导致的竞争
    QTimer::singleShot(0, this, [this, methods] {
        closeResetPasswordMessage();
        if (methods != ResetPasswordHelper::NoResetMethod && m_resetPasswordMessageVisible) {
            showResetPasswordMessage();
        }
    });
}

void AuthModule::resetPasswordCloseMessage()
{
    closeResetPasswordMessage();
}

void AuthModule::resetPasswordShowMessage(int methods)
{
    Q_UNUSED(methods)
    showResetPasswordMessage();
}

void AuthModule::showResetPasswordMessage()
{
    // 缓存未就绪时等待异步预取完成（不阻塞 UI），由 availableMethodsChanged 驱动
    if (!m_resetPasswordHelper->isMethodsCached()) {
        return;
    }
    const int methods = m_resetPasswordHelper->cachedResetMethods();

    if (m_resetPasswordFloatingMessage) {
        m_resetPasswordFloatingMessage->show();
        return;
    }

    QWidget *centerFrame = findResetPasswordCenterFrame();
    if (!centerFrame) {
        return;
    }

    QPalette pa;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    pa.setColor(QPalette::Window, QColor(247, 247, 247, 51));
#else
    pa.setColor(QPalette::Background, QColor(247, 247, 247, 51));
#endif
    pa.setColor(QPalette::Highlight, Qt::white);
    pa.setColor(QPalette::HighlightedText, Qt::black);
    m_resetPasswordFloatingMessage = new DFloatingMessage(DFloatingMessage::MessageType::ResidentType);
    m_resetPasswordFloatingMessage->setAttribute(Qt::WA_DeleteOnClose, false);
    m_resetPasswordFloatingMessage->setPalette(pa);
    // DFloatingMessage 中未放开seticonsize接口，无法设置图标大小，使用缩放函数会造成图标锯齿
    // 只能使用findChildren找到对应的图标控件来设置图标大小进行规避
    // DFloatingMessage中有两个按钮一个是DIconButton,另一个是继承于DIconButton的DDialogCloseButton，需要区分
    QList<DIconButton *> btnList = m_resetPasswordFloatingMessage->findChildren<DIconButton *>();
    foreach (const auto iconButton, btnList) {
        DDialogCloseButton *closeButton = qobject_cast<DDialogCloseButton *>(iconButton);
        if (closeButton) {
            continue;
        }
        iconButton->installEventFilter(this);
        m_iconButton = iconButton;
    }
    m_resetPasswordFloatingMessage->setIcon(QIcon("://misc/images/dss_warning.svg"));
    auto *resetBtn = new DPushButton(tr("Reset Password"));
    // 纯白色背景 + 黑色字体
    {
        DPalette dp = DPaletteHelper::instance()->palette(resetBtn);
        dp.setColor(DPalette::Light, Qt::white);
        dp.setColor(DPalette::Dark, Qt::white);
        dp.setColor(QPalette::ButtonText, Qt::black);
        dp.setColor(QPalette::HighlightedText, Qt::black);
        dp.setColor(DPalette::TextTitle, Qt::black);
        dp.setColor(DPalette::TextLively, Qt::black);
        dp.setColor(DPalette::TextTips, Qt::black);
        DPaletteHelper::instance()->setPalette(resetBtn, dp);
    }
    QMenu *menu = new QMenu(resetBtn);
    connect(menu, &QMenu::aboutToShow, menu, [menu]() {
        DPlatformWindowHandle handle(menu);
        handle.setWindowRadius(8);
    });
    if (methods & ResetPasswordHelper::VerificationCodeReset) {
        QAction *act = menu->addAction(tr("Verification Code"));
        act->setProperty("method", ResetPasswordHelper::VerificationCodeReset);
    }
    if (methods & ResetPasswordHelper::OfflineKeyReset) {
        QAction *act = menu->addAction(tr("Offline Key"));
        act->setProperty("method", ResetPasswordHelper::OfflineKeyReset);
    }
    if (methods & ResetPasswordHelper::SecurityQuestionReset) {
        const QString secConfig = m_resetPasswordHelper->securityQuestionsConfig();
        if (secConfig == "Hidden") {
            // Hidden：完全隐藏入口
        } else {
            QAction *act = menu->addAction(tr("Security Questions"));
            act->setProperty("method", ResetPasswordHelper::SecurityQuestionReset);
            if (secConfig == "Disabled")
                act->setEnabled(false);  // Disabled：灰色不可点击
        }
    }
    resetBtn->setMenu(menu);
    m_resetPasswordPushButton = resetBtn;
    connect(menu, &QMenu::triggered, this, [this](QAction *action) {
        int method = action->property("method").toInt();
        m_resetPasswordHelper->triggerResetPasswordByMethod(method);
        if (method != ResetPasswordHelper::SecurityQuestionReset) {
            m_resetDialogShow = true;
            emit m_resetPasswordFloatingMessage->closeButtonClicked();
        }
    });
    m_resetPasswordFloatingMessage->setWidget(resetBtn);
    m_resetPasswordFloatingMessage->setMessage(tr("Forgot password?"));
    connect(m_resetPasswordFloatingMessage.data(), &DFloatingMessage::closeButtonClicked,
            this, &AuthModule::onResetPasswordMessageCloseButtonClicked);
    DMessageManager::instance()->sendMessage(centerFrame, m_resetPasswordFloatingMessage.data());
}

void AuthModule::closeResetPasswordMessage()
{
    if (m_resetPasswordFloatingMessage) {
        m_resetPasswordPushButton.clear();
        m_resetPasswordFloatingMessage->close();
        m_resetPasswordFloatingMessage->deleteLater();
        m_resetPasswordFloatingMessage.clear();
    }
}

void AuthModule::updateResetPasswordUI()
{
    // 前置检查：域管账户或不满足显示条件直接跳过（不触发 DBus 调用）
    if (m_currentUid > 9999 || !m_resetPasswordHelper->isShowResetPasswordMessage()) {
        closeResetPasswordMessage();
        return;
    }

    // 缓存未就绪时等待异步预取完成，不阻塞 UI
    // 预取完成后通过 availableMethodsChanged 信号驱动 UI 更新
    if (!m_resetPasswordHelper->isMethodsCached()) {
        closeResetPasswordMessage();
        m_resetPasswordHelper->requestRefresh();
        return;
    }

    if (m_resetPasswordMessageVisible) {
        showResetPasswordMessage();
    } else {
        closeResetPasswordMessage();
    }
}

void AuthModule::clearResetPasswordCache()
{
    if (m_resetPasswordHelper) {
        m_resetPasswordHelper->clearCache();
    }
}

void AuthModule::requestRefreshResetPasswordCache()
{
    if (m_resetPasswordHelper) {
        m_resetPasswordHelper->requestRefresh();
    }
}

void AuthModule::setCurrentUid(uid_t uid)
{
    m_currentUid = uid;
    if (m_resetPasswordHelper) {
        m_resetPasswordHelper->setCurrentUid(uid);
    }
}

void AuthModule::setResetPasswordMessageVisible(bool isVisible)
{
    if (m_resetPasswordMessageVisible == isVisible)
        return;

    // 如果设置为显示重置按钮，失败次数>=3次就显示重置密码
    if (isVisible && m_limitsInfo && m_limitsInfo->numFailures < 3)
        return;

    m_resetPasswordMessageVisible = isVisible;
    emit resetPasswordMessageVisibleChanged(m_resetPasswordMessageVisible);
}

void AuthModule::onResetPasswordMessageCloseButtonClicked()
{
    m_resetPasswordMessageVisible = false;
    emit resetPasswordMessageVisibleChanged(false);
}

QWidget *AuthModule::findResetPasswordCenterFrame()
{
    QWidget *parent = parentWidget();
    if (!parent)
        return nullptr;
    return parent->parentWidget();
}
