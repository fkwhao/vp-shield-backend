package com.ethan.vpshield.config;

import com.ethan.vpshield.controller.TrafficWebSocketHandler;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * WebSocket 配置类
 * 注册 WebSocket 端点，供前端实时获取流量数据和告警信息
 */
@Configuration
@EnableWebSocket
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketConfigurer {

    private final TrafficWebSocketHandler trafficWebSocketHandler;

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        // 注册流量监控 WebSocket 端点
        // 前端通过 ws://host:port/ws/traffic 连接
        registry.addHandler(trafficWebSocketHandler, "/ws/traffic")
                .setAllowedOrigins("*");
    }
}