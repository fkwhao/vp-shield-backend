package com.ethan.vpshield.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * 异步任务配置
 * 为抓包和攻击模拟提供独立线程池，避免阻塞主线程
 */
@Configuration
@EnableAsync
@EnableScheduling
public class AsyncConfig {

    /**
     * 抓包专用线程池
     * 使用单线程确保包处理的顺序性和线程安全
     */
    @Bean(name = "packetCaptureExecutor")
    public Executor packetCaptureExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(0);
        executor.setThreadNamePrefix("pcap-");
        executor.initialize();
        return executor;
    }

    /**
     * 攻击模拟线程池
     */
    @Bean(name = "attackExecutor")
    public Executor attackExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("attack-");
        executor.initialize();
        return executor;
    }

    /**
     * 统计计算线程池
     * 用于防御检测的定时统计任务
     */
    @Bean(name = "statsExecutor")
    public Executor statsExecutor() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "stats-monitor");
            t.setDaemon(true);
            return t;
        });
    }
}