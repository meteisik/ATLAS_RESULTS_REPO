import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_OnyxOrbit {
    private static int privateFive = 5;

    private String loadOnyxOrbit() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_ORBIT_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runOnyxOrbit() throws SQLException {
        String data = loadOnyxOrbit();
        Connection onyxOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxOrbit");
        Statement onyxOrbitStatement = null;
        ResultSet onyxOrbitRows = null;
        try {
            onyxOrbitStatement = onyxOrbitConnection.createStatement();
            onyxOrbitRows = onyxOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(onyxOrbitRows.getRow());
        } finally {
            if (onyxOrbitRows != null) {
                onyxOrbitRows.close();
            }
            if (onyxOrbitStatement != null) {
                onyxOrbitStatement.close();
            }
            onyxOrbitConnection.close();
        }
    }
}
