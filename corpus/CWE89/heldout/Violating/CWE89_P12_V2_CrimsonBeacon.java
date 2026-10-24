import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonBeacon {
    private static boolean privateReturnsTrue() { return true; }

    public void runCrimsonBeacon() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_BEACON_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonBeaconBase baseObject = new CWE89_P12_V2_CrimsonBeaconSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonBeaconBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonBeaconSink extends CWE89_P12_V2_CrimsonBeaconBase {
    public void action(String data) throws SQLException {
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
