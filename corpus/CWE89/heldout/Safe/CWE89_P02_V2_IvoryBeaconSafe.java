import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_IvoryBeaconSafe {
    private static boolean privateTrue = true;

    public void runIvoryBeacon() throws SQLException {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
    }
}
