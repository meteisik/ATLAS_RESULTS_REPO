import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_OnyxBeaconSafe {

    public void runOnyxBeacon() throws SQLException {
        String data;
        data = "foo";
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_OnyxBeaconSafeSink()).queryOnyxBeacon(dataArray);
    }
}

class CWE89_P08_V1_OnyxBeaconSafeSink {
    public void queryOnyxBeacon(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection onyxBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxBeacon");
        Statement onyxBeaconStatement = null;
        ResultSet onyxBeaconRows = null;
        try {
            onyxBeaconStatement = onyxBeaconConnection.createStatement();
            onyxBeaconRows = onyxBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxBeaconRows.getRow());
        } finally {
            if (onyxBeaconRows != null) {
                onyxBeaconRows.close();
            }
            if (onyxBeaconStatement != null) {
                onyxBeaconStatement.close();
            }
            onyxBeaconConnection.close();
        }
    }
}
