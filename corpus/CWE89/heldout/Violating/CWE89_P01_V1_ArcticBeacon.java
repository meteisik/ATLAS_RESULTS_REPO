import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V1_ArcticBeacon {

    public void runArcticBeacon() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_BEACON_FILTER");
        Connection arcticBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticBeacon");
        Statement arcticBeaconStatement = null;
        ResultSet arcticBeaconRows = null;
        try {
            arcticBeaconStatement = arcticBeaconConnection.createStatement();
            arcticBeaconRows = arcticBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(arcticBeaconRows.getRow());
        } finally {
            if (arcticBeaconRows != null) {
                arcticBeaconRows.close();
            }
            if (arcticBeaconStatement != null) {
                arcticBeaconStatement.close();
            }
            arcticBeaconConnection.close();
        }
    }
}
