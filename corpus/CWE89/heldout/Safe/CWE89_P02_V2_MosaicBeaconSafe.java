import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_MosaicBeaconSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runMosaicBeacon() throws SQLException {
        String dataCopy;
        {
            String data;
            if (IO.staticFive == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
}
