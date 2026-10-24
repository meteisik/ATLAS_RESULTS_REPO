import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P01_V2_IvoryOrbit {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runIvoryOrbit() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("IVORY_ORBIT_FILTER");
        } else {
            data = null;
        }
        Connection ivoryOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryOrbit");
        Statement ivoryOrbitStatement = null;
        ResultSet ivoryOrbitRows = null;
        try {
            ivoryOrbitStatement = ivoryOrbitConnection.createStatement();
            ivoryOrbitRows = ivoryOrbitStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(ivoryOrbitRows.getRow());
        } finally {
            if (ivoryOrbitRows != null) {
                ivoryOrbitRows.close();
            }
            if (ivoryOrbitStatement != null) {
                ivoryOrbitStatement.close();
            }
            ivoryOrbitConnection.close();
        }
    }
}
