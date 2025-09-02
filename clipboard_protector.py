import hashlib
import time
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QClipboard
from utils import log_event

class ClipboardMonitorThread(QThread):
    """Отдельный поток для мониторинга буфера обмена"""
    clipboard_changed = pyqtSignal(str, str)  # content_type, hash
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.last_text_hash = ""
        self.last_image_hash = ""
        self.check_interval = 500  # мс
        
    def run(self):
        while self.running:
            try:
                clipboard = QApplication.clipboard()
                self._check_text_content(clipboard)
                self._check_image_content(clipboard)
                self.msleep(self.check_interval)
            except Exception as e:
                log_event(f"Ошибка в мониторе буфера обмена: {e}")
                self.msleep(1000)
    
    def _check_text_content(self, clipboard):
        """Проверка текстового содержимого"""
        text = clipboard.text()
        if text:
            text_hash = hashlib.md5(text.encode()).hexdigest()
            if text_hash != self.last_text_hash:
                self.last_text_hash = text_hash
                self.clipboard_changed.emit("text", text_hash)
    
    def _check_image_content(self, clipboard):
        """Проверка изображений в буфере"""
        mime_data = clipboard.mimeData()
        if mime_data and mime_data.hasImage():
            # Получаем байтовое представление изображения
            image_data = mime_data.data("image/png")
            if image_data:
                image_hash = hashlib.md5(image_data.data()).hexdigest()
                if image_hash != self.last_image_hash:
                    self.last_image_hash = image_hash
                    self.clipboard_changed.emit("image", image_hash)
    
    def stop(self):
        self.running = False
        self.quit()
        self.wait()

class ClipboardProtector:
    def __init__(self, parent, callback, config=None):
        self.parent = parent
        self.callback = callback
        self.is_active = True
        
        # Конфигурация
        self.config = config or {}
        self.protection_level = self.config.get('protection_level', 'medium')
        self.allowed_formats = self.config.get('allowed_formats', [])
        self.whitelist_apps = self.config.get('whitelist_apps', [])
        self.max_violations = self.config.get('max_violations', 3)
        
        # Статистика нарушений
        self.violation_count = 0
        self.violation_history = []
        self.blocked_content_hashes = set()
        
        # Запуск мониторинга
        self._init_monitoring()
        log_event(f"ClipboardProtector запущен с уровнем защиты: {self.protection_level}")
    
    def _init_monitoring(self):
        """Инициализация системы мониторинга"""
        # Основной таймер для быстрых проверок
        self.timer = QTimer()
        self.timer.timeout.connect(self._quick_check)
        self.timer.start(200)
        
        # Фоновый поток для детального мониторинга
        self.monitor_thread = ClipboardMonitorThread()
        self.monitor_thread.clipboard_changed.connect(self._handle_clipboard_change)
        self.monitor_thread.start()
        
        # Таймер для очистки истории нарушений
        self.cleanup_timer = QTimer()
        self.cleanup_timer.timeout.connect(self._cleanup_old_violations)
        self.cleanup_timer.start(60000)  # каждую минуту
    
    def _quick_check(self):
        """Быстрая проверка буфера обмена"""
        if not self.is_active:
            return
            
        try:
            clipboard = QApplication.clipboard()
            
            # Проверка на подозрительные форматы
            mime_data = clipboard.mimeData()
            if mime_data:
                formats = mime_data.formats()
                
                # Блокировка опасных форматов
                dangerous_formats = [
                    'application/x-qt-windows-mime;value="FileName"',
                    'application/x-qt-windows-mime;value="FileNameW"',
                    'text/uri-list'
                ]
                
                for dangerous_format in dangerous_formats:
                    if dangerous_format in formats:
                        self._handle_violation("dangerous_format", dangerous_format)
                        return
                
                # Проверка размера содержимого
                if self._is_content_too_large(mime_data):
                    self._handle_violation("content_too_large", "")
                    return
                    
        except Exception as e:
            log_event(f"Ошибка в quick_check: {e}")
    
    def _handle_clipboard_change(self, content_type, content_hash):
        """Обработка изменений в буфере обмена"""
        if not self.is_active:
            return
            
        try:
            # Проверка на повторное копирование заблокированного контента
            if content_hash in self.blocked_content_hashes:
                self._handle_violation("blocked_content_retry", content_type)
                return
            
            # Проверка уровня защиты
            if self.protection_level == "strict":
                # В строгом режиме блокируем любое копирование
                self._handle_violation("strict_mode", content_type)
                return
            elif self.protection_level == "medium":
                # В среднем режиме анализируем контент
                if self._is_suspicious_content(content_type, content_hash):
                    self._handle_violation("suspicious_content", content_type)
                    return
            
            # Уведомляем о разрешенном копировании
            self.callback()
            log_event(f"Обнаружено копирование: {content_type} (hash: {content_hash[:8]}...)")
            
        except Exception as e:
            log_event(f"Ошибка в _handle_clipboard_change: {e}")
    
    def _is_content_too_large(self, mime_data):
        """Проверка размера контента"""
        max_size = self.config.get('max_content_size', 10 * 1024 * 1024)  # 10MB
        
        try:
            for format_name in mime_data.formats():
                data = mime_data.data(format_name)
                if data and len(data.data()) > max_size:
                    return True
        except:
            pass
        return False
    
    def _is_suspicious_content(self, content_type, content_hash):
        """Анализ подозрительного контента"""
        if content_type == "text":
            clipboard = QApplication.clipboard()
            text = clipboard.text()
            
            # Проверка на подозрительные паттерны
            suspicious_patterns = [
                "password", "пароль", "secret", "секрет",
                "token", "токен", "key", "ключ", "api",
                "confidential", "конфиденциально"
            ]
            
            text_lower = text.lower()
            for pattern in suspicious_patterns:
                if pattern in text_lower:
                    return True
            
            # Проверка на слишком длинный текст
            if len(text) > self.config.get('max_text_length', 10000):
                return True
        
        return False
    
    def _handle_violation(self, violation_type, details):
        """Обработка нарушения"""
        timestamp = time.time()
        violation = {
            'type': violation_type,
            'details': details,
            'timestamp': timestamp
        }
        
        self.violation_history.append(violation)
        self.violation_count += 1
        
        # Очистка буфера обмена
        self._force_clear_clipboard()
        
        # Добавление в черный список
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        if text:
            content_hash = hashlib.md5(text.encode()).hexdigest()
            self.blocked_content_hashes.add(content_hash)
        
        # Логирование
        log_event(f"Нарушение защиты: {violation_type} - {details}")
        log_event(f"Общее количество нарушений: {self.violation_count}")
        
        # Проверка превышения лимита
        if self.violation_count >= self.max_violations:
            self._escalate_protection()
        
        # Вызов callback с информацией о нарушении
        if hasattr(self.callback, '__call__'):
            try:
                self.callback(violation)
            except:
                self.callback()
    
    def _force_clear_clipboard(self):
        """Принудительная очистка буфера обмена"""
        try:
            clipboard = QApplication.clipboard()
            clipboard.clear(QClipboard.Mode.Clipboard)
            clipboard.clear(QClipboard.Mode.Selection)  # Для Linux
            
            # Дополнительная очистка для Windows
            import platform
            if platform.system() == "Windows":
                try:
                    import ctypes
                    ctypes.windll.user32.OpenClipboard(0)
                    ctypes.windll.user32.EmptyClipboard()
                    ctypes.windll.user32.CloseClipboard()
                except:
                    pass
                    
        except Exception as e:
            log_event(f"Ошибка при очистке буфера: {e}")
    
    def _escalate_protection(self):
        """Эскалация защиты при превышении лимита нарушений"""
        log_event("КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ: Превышен лимит нарушений!")
        
        # Переход в строгий режим
        if self.protection_level != "strict":
            self.protection_level = "strict"
            log_event("Автоматический переход в строгий режим защиты")
        
        # Уменьшение интервала проверки
        if self.timer.interval() > 100:
            self.timer.setInterval(100)
            log_event("Увеличена частота мониторинга буфера обмена")
        
        # Дополнительные меры (можно расширить)
        self._notify_security_incident()
    
    def _notify_security_incident(self):
        """Уведомление о серьезном нарушении безопасности"""
        # Здесь можно добавить отправку уведомлений, логирование в файл и т.д.
        log_event("Зафиксирован инцидент безопасности - множественные попытки копирования")
    
    def _cleanup_old_violations(self):
        """Очистка старых записей о нарушениях"""
        current_time = time.time()
        cleanup_threshold = 3600  # 1 час
        
        self.violation_history = [
            v for v in self.violation_history 
            if current_time - v['timestamp'] < cleanup_threshold
        ]
        
        # Обновление счетчика нарушений
        self.violation_count = len(self.violation_history)
    
    def get_statistics(self):
        """Получение статистики работы защиты"""
        return {
            'total_violations': len(self.violation_history),
            'recent_violations': len([
                v for v in self.violation_history 
                if time.time() - v['timestamp'] < 300  # последние 5 минут
            ]),
            'protection_level': self.protection_level,
            'blocked_hashes_count': len(self.blocked_content_hashes),
            'is_active': self.is_active
        }
    
    def set_protection_level(self, level):
        """Изменение уровня защиты"""
        valid_levels = ['low', 'medium', 'strict']
        if level in valid_levels:
            self.protection_level = level
            log_event(f"Уровень защиты изменен на: {level}")
        else:
            log_event(f"Недопустимый уровень защиты: {level}")
    
    def pause(self):
        """Приостановка защиты"""
        self.is_active = False
        log_event("Защита буфера обмена приостановлена")
    
    def resume(self):
        """Возобновление защиты"""
        self.is_active = True
        log_event("Защита буфера обмена возобновлена")
    
    def add_to_whitelist(self, content_hash):
        """Добавление контента в белый список"""
        self.blocked_content_hashes.discard(content_hash)
        log_event(f"Контент добавлен в белый список: {content_hash[:8]}...")
    
    def clear(self):
        """Завершение работы защиты"""
        try:
            self.is_active = False
            
            if hasattr(self, 'timer'):
                self.timer.stop()
                
            if hasattr(self, 'cleanup_timer'):
                self.cleanup_timer.stop()
                
            if hasattr(self, 'monitor_thread'):
                self.monitor_thread.stop()
            
            # Финальная очистка буфера
            self._force_clear_clipboard()
            
            log_event("ClipboardProtector остановлен и буфер обмена очищен")
            
        except Exception as e:
            log_event(f"Ошибка при завершении работы ClipboardProtector: {e}")