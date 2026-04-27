package com.ethan.vpshield.controller;

import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * WebSocket 处理器
 * 负责向前端推送实时流量统计和告警信息
 *
 * 消息类型：
 * - stats: 流量统计数据
 * - alert: 安全告警
 */
@Slf4j
@Component
public class TrafficWebSocketHandler extends TextWebSocketHandler {

    /** 已连接的 WebSocket 会话列表 */
    private final CopyOnWriteArrayList<WebSocketSession> sessions = new CopyOnWriteArrayList<>();

    /** JSON 序列化器 */
    private final ObjectMapper objectMapper;

    public TrafficWebSocketHandler() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * 新连接建立
     */
    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        sessions.add(session);
        log.info("WebSocket 连接建立: {}, 当前连接数: {}", session.getId(), sessions.size());
    }

    /**
     * 连接关闭
     */
    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        sessions.remove(session);
        log.info("WebSocket 连接关闭: {}, 状态: {}, 当前连接数: {}",
                session.getId(), status, sessions.size());
    }

    /**
     * 处理传输错误
     */
    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        log.error("WebSocket 传输错误: {}", session.getId(), exception);
        sessions.remove(session);
    }

    /**
     * 推送流量统计数据
     *
     * @param stats 统计数据
     */
    public void broadcastStats(TrafficStats stats) {
        try {
            WebSocketMessage message = new WebSocketMessage("stats", stats);
            String json = objectMapper.writeValueAsString(message);
            broadcast(json);
        } catch (Exception e) {
            log.error("序列化统计数据失败", e);
        }
    }

    /**
     * 推送告警信息
     *
     * @param alert 告警
     */
    public void broadcastAlert(Alert alert) {
        try {
            WebSocketMessage message = new WebSocketMessage("alert", alert);
            String json = objectMapper.writeValueAsString(message);
            log.info("Broadcasting alert: {}", json);
            broadcast(json);
        } catch (Exception e) {
            log.error("序列化告警信息失败", e);
        }
    }

    /**
     * 广播消息到所有连接
     */
    private void broadcast(String message) {
        TextMessage textMessage = new TextMessage(message);

        for (WebSocketSession session : sessions) {
            if (session.isOpen()) {
                try {
                    session.sendMessage(textMessage);
                } catch (IOException e) {
                    log.warn("发送消息失败: {}", session.getId(), e);
                }
            }
        }
    }

    /**
     * WebSocket 消息结构
     */
    public record WebSocketMessage(String type, Object data) {}
}