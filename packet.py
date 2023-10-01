from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, QLabel
from PyQt5.QtCore import QTimer, Qt, QSize, QDateTime
from scapy.all import *
from catboost import CatBoostClassifier, Pool
import numpy as np
import pandas as pd
import threading
import queue
import json


class PacketCaptureThread(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.stop_event = threading.Event()
        self.last_time = None
        # Initialize packet count
        self.packet_count = 0

        # Initialize abnormal packet count
        self.abnormal_count = 0

        # Initialize abnormal packet log
        self.abnormal_log = []

        # Initialize classifier
        self.clf = CatBoostClassifier(cat_features=["Dst Port"])
        self.clf.load_model('catboost_selected_model')

    def run(self):
        sniff(prn=self.packet_callback, stop_filter=self.stop_filter)  # Use stop filter as stop filter

    def packet_callback(self, packet):
        # Extract features
        features = {}
        if packet.haslayer(TCP):
            fwd_seg_size_min = packet[TCP].options[0][1] if packet[TCP].options else 0
            init_bwd_win_byts = packet[TCP].window
            init_fwd_win_byts = packet[TCP].options[2][1][0] if len(packet[TCP].options) > 2 else 0
            subflow_bwd_byts = packet[TCP].ack - packet[TCP].seq
            subflow_fwd_byts = len(packet[TCP].payload)
            dst_port = packet[TCP].dport

            features['Dst Port'] = dst_port
            features['Fwd IAT Min'] = packet.time - self.last_time if self.last_time else 0
            features['Fwd Pkts/s'] = subflow_fwd_byts / packet.time
            features['Subflow Bwd Byts'] = subflow_bwd_byts
            features['Init Fwd Win Byts'] = init_fwd_win_byts
            features['Init Bwd Win Byts'] = init_bwd_win_byts
            features['Fwd Seg Size Min'] = fwd_seg_size_min

            # Update packet count
            self.packet_count += 1

            # Create Pool object
            features_df = pd.DataFrame.from_dict([features])
            features_pool = Pool(data=features_df, cat_features=["Dst Port"])

            # Use model to predict
            prediction = self.clf.predict(features_pool)

            # Add features and prediction to queue
            self.queue.put((features, prediction))

    def stop_filter(self, packet):
        return self.stop_event.is_set()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Set window size
        self.setGeometry(100, 100, 2000, 900)

        # Create buttons
        self.attack_button = QPushButton('Attack', self)
        self.start_button = QPushButton('Start Recording', self)
        self.pause_button = QPushButton('Pause Recording', self)

        # Create tree widget to display packet history
        self.packet_history = QTreeWidget(self)

        # Set tree widget size
        self.packet_history.setFixedSize(1600, 400)

        # Set item width
        self.packet_history.setColumnWidth(0, 300)

        # Create label to display packet count and abnormal count
        self.info_label = QLabel(self)

        # Create horizontal layouts for packet_history and predict_output
        h_layout1 = QHBoxLayout()
        h_layout1.addWidget(self.attack_button)

        h_layout2 = QHBoxLayout()
        h_layout2.addWidget(self.start_button)
        h_layout2.addWidget(self.pause_button)

        h_layout3 = QHBoxLayout()
        h_layout3.addWidget(self.packet_history)

        # Set fixed height for each widget in h_layout3
        fixed_height = 400  # set the desired fixed height
        self.packet_history.setFixedHeight(fixed_height)
        self.info_label.setFixedHeight(fixed_height)

        # Set start_button and pause_button width
        self.start_button.setFixedWidth(150)
        self.pause_button.setFixedWidth(150)
        self.attack_button.setFixedWidth(150)
        h_layout2.setAlignment(Qt.AlignLeft)

        # Create vertical layout for all horizontal layouts
        v_layout = QVBoxLayout()
        v_layout.addLayout(h_layout1)
        v_layout.addLayout(h_layout2)
        v_layout.addLayout(h_layout3)
        v_layout.addWidget(self.info_label)

        # Set layout for main window
        central_widget = QWidget()
        central_widget.setLayout(v_layout)
        self.setCentralWidget(central_widget)

        # Connect buttons to functions
        self.attack_button.clicked.connect(self.attack)
        self.start_button.clicked.connect(self.start_recording)
        self.pause_button.clicked.connect(self.pause_recording)

        # Initialize packet capture thread and queue
        self.packet_queue = queue.Queue()
        self.packet_capture_thread = None  # Initialize packet_capture_thread to None

        # Initialize QTimer to periodically check the queue for new packets
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_packet_display)
        self.timer.start(100)

        # Connect itemClicked signal of packet_history to function that updates packet_info
        self.packet_history.itemClicked.connect(self.update_packet_info)

    def update_packet_info(self, item):
        pass

    def update_packet_display(self):
        # Check if there are new packets in the queue
        while not self.packet_queue.empty():
            features, prediction = self.packet_queue.get()
            if prediction[0] == 0:
                prediction = '正常'
            else:
                prediction = '異常'

            # Create tree widget item
            item = QTreeWidgetItem(self.packet_history)
            current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            item.setText(0, f"{current_time} predict: {prediction}")

            # Add feature sub-items
            for feature_name, feature_value in features.items():
                sub_item = QTreeWidgetItem(item)
                sub_item.setText(0, f"{feature_name}: {feature_value}")

            # Add item to packet history
            self.packet_history.addTopLevelItem(item)

            # Update information label
            self.info_label.setText(f"Packet Count: {self.packet_capture_thread.packet_count} Abnormal Count: {self.packet_capture_thread.abnormal_count}")

    def attack(self):
        # Generate abnormal traffic and add to packet stream
        pass

    def start_recording(self):
        # Stop previous packet capture thread if it is running
        if self.packet_capture_thread and self.packet_capture_thread.is_alive():
            self.packet_capture_thread.stop_event.set()
            self.packet_capture_thread.join()

        # Start capturing packets
        self.packet_capture_thread = PacketCaptureThread(self.packet_queue)
        self.packet_capture_thread.last_time = None  # Initialize last_time to None
        self.packet_capture_thread.packet_count = 0
        self.packet_capture_thread.abnormal_count = 0
        self.packet_capture_thread.abnormal_log = []
        self.packet_capture_thread.start()
        self.update_packet_display()

    def pause_recording(self):
        # Stop capturing packets
        self.packet_capture_thread.stop_event.set()


if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()