import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void runAmberSundial() throws SQLException {
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberSundialSafeSink()).queryAmberSundial();
    }
}

class CWE89_P10_V2_AmberSundialSafeSink {
    public void queryAmberSundial() throws SQLException {
        String data = CWE89_P10_V2_AmberSundialSafe.data;
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        Statement amberSundialStatement = null;
        ResultSet amberSundialRows = null;
        try {
            amberSundialStatement = amberSundialConnection.createStatement();
            amberSundialRows = amberSundialStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberSundialRows.getRow());
        } finally {
            if (amberSundialRows != null) {
                amberSundialRows.close();
            }
            if (amberSundialStatement != null) {
                amberSundialStatement.close();
            }
            amberSundialConnection.close();
        }
    }
}
