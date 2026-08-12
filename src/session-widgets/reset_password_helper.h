// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef RESETPASSWORDHELPER_H
#define RESETPASSWORDHELPER_H

#include <QObject>
#include <QTimer>
#include <QDBusPendingCallWatcher>
#include <DConfig>

#include <sys/types.h>

class ResetPasswordHelper : public QObject
{
    Q_OBJECT
public:
    enum ResetMethod {
        NoResetMethod = 0,
        VerificationCodeReset = 1,
        SecurityQuestionReset = 2,
        OfflineKeyReset = 4
    };

    explicit ResetPasswordHelper(QObject *parent = nullptr);

    void setCurrentUid(uid_t uid);
    int availableResetMethods();
    bool hasSecurityQuestionsConfigured();
    bool hasSecretKey();
    bool isShowResetPasswordMessage() const;
    QString resetPasswordButtonText(int methods) const;
    QString securityQuestionsConfig();
    void triggerResetPasswordByMethod(int method);

    // 异步预取可用重置方法（不阻塞 UI 线程）
    void refreshAvailableMethods();
    // 清除所有 DBus 缓存（解锁成功后调用，下次锁屏自动重新缓存）
    void clearCache();
    // 请求刷新缓存（re-lock 时调用，确保使用最新数据）
    void requestRefresh();
    // 获取缓存的可用重置方法（不发起 DBus 调用）
    int cachedResetMethods() const { return m_cachedResetMethods; }
    // 缓存是否已就绪
    bool isMethodsCached() const { return m_methodsCached; }

signals:
    void requestSecurityQuestionReset();
    void requestResetPasswordDialogStateChanged(bool visible);
    // 异步刷新完成后发射，通知 UI 更新
    void availableMethodsChanged(int methods);

private:
    // 同步计算并更新缓存（首次调用）
    int computeAvailableMethods();
    // 异步查询全部结束后更新缓存并发射信号
    void onAsyncQueryFinished(int gen = 0);
    // 重新读取 DConfig 值
    void reloadDConfig();
    // DConfig valueChanged 信号处理
    void onDConfigValueChanged(const QString &key);

    uid_t m_currentUid = 0;
    QString m_securityQuestionsConfig;
    bool m_securityQuestionsChecked = false;
    bool m_securityQuestionsConfigured = false;
    // 延迟刷新标志：clearCache 后阻止立即刷新，由下次 showEvent 触发
    bool m_deferRefresh = false;

    // 可用重置方法缓存
    int m_cachedResetMethods = NoResetMethod;
    bool m_methodsCached = false;
    // 正在进行的异步查询计数
    int m_pendingAsyncCalls = 0;

    // 密钥缓存
    bool m_secretKeyCached = false;
    bool m_secretKeyResult = false;

    // 缓存版本号：clearCache 时递增，异步回调校验以丢弃过期结果
    int m_cacheGeneration = 0;
    // 防重入标志：refreshAvailableMethods 执行期间为 true，防止同步 DBus 调用导致的计数器提前递减问题
    bool m_isRefreshingMethods = false;

    Dtk::Core::DConfig *m_dconfig = nullptr;
};

#endif // RESETPASSWORDHELPER_H
