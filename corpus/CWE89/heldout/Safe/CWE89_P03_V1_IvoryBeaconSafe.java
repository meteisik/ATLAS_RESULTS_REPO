import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_IvoryBeaconSafe {

    private void queryIvoryBeacon(String data) throws SQLException {
        Connection ivoryBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryBeacon");
        Statement ivoryBeaconStatement = null;
        ResultSet ivoryBeaconRows = null;
        try {
            ivoryBeaconStatement = ivoryBeaconConnection.createStatement();
            ivoryBeaconRows = ivoryBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryBeaconRows.getRow());
        } finally {
            if (ivoryBeaconRows != null) {
                ivoryBeaconRows.close();
            }
            if (ivoryBeaconStatement != null) {
                ivoryBeaconStatement.close();
            }
            ivoryBeaconConnection.close();
        }
    }

    public void runIvoryBeacon() throws SQLException {
        String data;
        data = "foo";
        queryIvoryBeacon(data);
    }
}
