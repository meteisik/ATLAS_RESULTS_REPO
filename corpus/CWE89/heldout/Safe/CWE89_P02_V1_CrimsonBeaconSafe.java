import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_CrimsonBeaconSafe {

    public void runCrimsonBeacon() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection crimsonBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonBeacon");
            Statement crimsonBeaconStatement = null;
            ResultSet crimsonBeaconRows = null;
            try {
                crimsonBeaconStatement = crimsonBeaconConnection.createStatement();
                crimsonBeaconRows = crimsonBeaconStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(crimsonBeaconRows.getRow());
            } finally {
                if (crimsonBeaconRows != null) {
                    crimsonBeaconRows.close();
                }
                if (crimsonBeaconStatement != null) {
                    crimsonBeaconStatement.close();
                }
                crimsonBeaconConnection.close();
            }
        }
    }
}
