import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_MosaicBeacon {

    public void runMosaicBeacon() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_BEACON_FILTER");
        (new CWE89_P06_V1_MosaicBeaconSink()).queryMosaicBeacon(data);
    }
}

class CWE89_P06_V1_MosaicBeaconSink {
    public void queryMosaicBeacon(String data) throws SQLException {
        Connection mosaicBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicBeacon");
        Statement mosaicBeaconStatement = null;
        ResultSet mosaicBeaconRows = null;
        try {
            mosaicBeaconStatement = mosaicBeaconConnection.createStatement();
            mosaicBeaconRows = mosaicBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(mosaicBeaconRows.getRow());
        } finally {
            if (mosaicBeaconRows != null) {
                mosaicBeaconRows.close();
            }
            if (mosaicBeaconStatement != null) {
                mosaicBeaconStatement.close();
            }
            mosaicBeaconConnection.close();
        }
    }
}
