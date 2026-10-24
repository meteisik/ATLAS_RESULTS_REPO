import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_CrimsonBeaconSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runCrimsonBeacon() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_CrimsonBeaconSafeBase baseObject = new CWE89_P12_V2_CrimsonBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_CrimsonBeaconSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_CrimsonBeaconSafeSink extends CWE89_P12_V2_CrimsonBeaconSafeBase {
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
