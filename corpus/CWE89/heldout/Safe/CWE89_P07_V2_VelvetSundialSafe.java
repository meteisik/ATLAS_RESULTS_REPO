import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_VelvetSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runVelvetSundial() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE89_P07_V2_VelvetSundialSafeSource()).loadVelvetSundial();
        } else {
            data = null;
        }
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        Statement velvetSundialStatement = null;
        ResultSet velvetSundialRows = null;
        try {
            velvetSundialStatement = velvetSundialConnection.createStatement();
            velvetSundialRows = velvetSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(velvetSundialRows.getRow());
        } finally {
            if (velvetSundialRows != null) {
                velvetSundialRows.close();
            }
            if (velvetSundialStatement != null) {
                velvetSundialStatement.close();
            }
            velvetSundialConnection.close();
        }
    }
}

class CWE89_P07_V2_VelvetSundialSafeSource {
    public String loadVelvetSundial() {
        String data;
        data = "foo";
        return data;
    }
}
