import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_MosaicBeaconSafe {

    private String mosaicBeaconData;

    private void queryMosaicBeacon() throws SQLException {
        String data = mosaicBeaconData;
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

    public void runMosaicBeacon() throws SQLException {
        String data;
        data = "foo";
        mosaicBeaconData = data;
        queryMosaicBeacon();
    }
}
