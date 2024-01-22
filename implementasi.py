from scapy.all import sniff, Ether, IP, TCP
import psutil
import time
import datetime
import joblib
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from telegram import Bot
import asyncio
from asyncio import get_event_loop
import threading
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
import queue

TELEGRAM_TOKEN = '6232931773:AAGVVlH8A0mv0cRH_M0fGvha5SjRI39r4Vs'
TELEGRAM_CHAT_ID = '5452160265'

model = joblib.load('model_implementasi.pkl')


# statistik jaringan sebelumnya
prev_stats = {}

stop_sniffing = False
stop_event = threading.Event()
packet_queue = queue.Queue()

jumlah_packet = 0
batas = 15
reset_jumlah_packet = True
last_packet_time = time.time()

async def send_telegram_notification(message):
    bot = Bot(token=TELEGRAM_TOKEN)
    await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode="Markdown")


def notify_telegram(message):
    asyncio.run(send_telegram_notification(message))
    
def pilih_fitur(packet):
    global prev_stats

    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        tcp_srcport = packet[TCP].sport
        frame_len = len(packet)
        tcp_flags_push = 1 if packet[TCP].flags =='P' else 0
        ip_flags_df = 1 if packet[IP].flags =="DF" else 0
        packets = int(len(packet) / 54)
        bytes = len(packet)

        #statistik jaringan saat ini
        network_stats = psutil.net_io_counters(pernic=True)
        interface = packet.sniffed_on

        if interface not in prev_stats:
            prev_stats[interface] = network_stats[interface]
        
        tx_packets = network_stats[interface].packets_sent - prev_stats[interface].packets_sent
        tx_bytes = network_stats[interface].bytes_sent -  prev_stats[interface].bytes_sent
        rx_packets = network_stats[interface].packets_recv - prev_stats[interface].packets_recv
        rx_bytes = network_stats[interface].bytes_recv - prev_stats[interface].bytes_recv

        prev_stats[interface] = network_stats[interface]

        return [ip_src, tcp_srcport, frame_len, tcp_flags_push, ip_flags_df, 
                packets, bytes, tx_packets, tx_bytes, rx_packets, rx_bytes]

def konversi_data_packet(packet_data):
    columns = ['ip.src', 'tcp.srcport', 'frame.len', 'tcp.flags.push', 'ip.flags.df', 
               'Packets','Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes']
    return pd.DataFrame([packet_data], columns=columns)

def bersihkan_data(packet_df):
    packet_df = packet_df.drop_duplicates()
    packet_df = packet_df.dropna()
    return packet_df


def scaling(packet_df):
    scaler = MinMaxScaler()
    fitur_scaling = ['tcp.srcport', 'frame.len', 'Packets','Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes']
    packet_df[fitur_scaling] = scaler.fit_transform(packet_df[fitur_scaling])
    return packet_df

def prediksi(packet_df, model):
    pred_packet = packet_df.drop(['ip.src'], axis=1)
    prediction = model.predict(pred_packet)
    return prediction

def packet_callback(packet):
    global jumlah_packet, batas, reset_jumlah_packet, last_packet_time, hitung
    packet_queue.put(packet)

    if reset_jumlah_packet:
        reset_jumlah_packet = False
        packet_queue.empty()    

    if IP in packet and TCP in packet:
        packet_data = pilih_fitur(packet)
        packet_df = konversi_data_packet(packet_data)
        packet_df = bersihkan_data(packet_df)
        packet_df = scaling(packet_df)
        

        # prediksi dengan model yang sudah dilatih
        prediction = prediksi(packet_df, model)

        print(f'Packet captured: {packet.summary()}')

        #time.sleep(0.5)

        # prediksi lalu lintas
        if prediction == 1 or prediction== 2:
            jumlah_packet +=1
            pesan = f"Terdeteksi Serangan DDoS pada jaringan.\nIP yang terdeteksi: {packet_data[0]}\nPada tanggal {datetime.date.today()} pada jam {datetime.datetime.now().time()} Wib.\n"
            print(pesan)

            if jumlah_packet == batas:
                notify_telegram(pesan)
                jumlah_packet = 0
                reset_jumlah_packet = True
        else:
            jumlah_packet = 0
            pesan = "Lalu Lintas Jaringan Normal. \n"
            print(pesan)
            reset_jumlah_packet = True

    #reset paket 
    if time.time() - last_packet_time > 1:
        last_packet_time = time.time()
        if packet_queue.qsize() > 0:
            print("Reset antrian paket karena tidak ada paket baru dalam satu detik.")
            packet_queue.queue.clear()


def start_sniffing():
    while not stop_event.is_set():
        try:
            packet = packet_queue.get(timeout=1)
            packet_callback(packet)
        except queue.Empty:
            continue

def process_packet(packet):
    packet_callback(packet)

def signal_handler(signal, frame):
    global stop_sniffing
    print("\nBerhenti mendeteksi lalu lintas jaringan...")
    stop_sniffing = True
    stop_event.set()
    sys.exit(0)

if __name__ == "__main__":
    print("Deteksi lalu lintas jaringan...")

    filter_rule = 'ip and tcp'

    # memberikan sinyal saat menekan Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # thread sniffing
    sniff_thread = threading.Thread(target=start_sniffing)

    try:
        sniff_thread.start()
        sniff(prn=lambda x: packet_queue.put(x), filter=filter_rule,iface='Wi-Fi', store=0)

    except KeyboardInterrupt:
        print("\nStopping network traffic detection...")
        stop_sniffing = True
        stop_event.set()

    finally:
        sniff_thread.join()

<<<<<<< HEAD
    print("Network traffic detection stopped.")
=======
    print("Network traffic detection stopped.")
>>>>>>> d4055b958f5184fc77c3a7584230803b06e4e7e5
