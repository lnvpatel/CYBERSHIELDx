import speedtest

def get_internet_speed():
    """Performs an internet speed test and returns download speed, upload speed, and ping."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        
        # Measure speeds
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping = st.results.ping  # Ping in ms

        # Get server details
        server_info = st.best
        isp = st.config["client"]["isp"]  # Get ISP info
        
        # Return results
        return {
            "download_speed_mbps": round(download_speed, 2),
            "upload_speed_mbps": round(upload_speed, 2),
            "ping_ms": round(ping, 2),
            "server": server_info["host"],
            "country": server_info["country"],
            "isp": isp,
            "message": "Internet speed test completed successfully"
        }

    except speedtest.ConfigRetrievalError:
        return {"error": "Failed to retrieve speedtest configuration. Check your internet connection."}
    
    except speedtest.NoMatchedServers:
        return {"error": "No matched servers found. Try again later."}
    
    except speedtest.SpeedtestException as e:
        return {"error": f"Speed test failed: {e}"}
    
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}

