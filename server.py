from flask import Flask, request
import ali
app = Flask("ali_ddns_http")


@app.route('/update', methods=['get'])
def update():
    ip = request.args.get("ip")
    if not ip == None:
        ali.update_by_ip(ip)
        return "update finished"
    else:
        return 'bad ip'


def main():
    config = ali.read_yaml('config.yaml')
    port = config['port']
    app.run(host='0.0.0.0', port=port)


if __name__ == '__main__':
    main()
