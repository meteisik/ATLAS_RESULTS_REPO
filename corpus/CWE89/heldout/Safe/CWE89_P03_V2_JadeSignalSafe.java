import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V2_JadeSignalSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void queryJadeSignal(String data) throws SQLException {
        Connection jadeSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeSignal");
        Statement jadeSignalStatement = null;
        ResultSet jadeSignalRows = null;
        try {
            jadeSignalStatement = jadeSignalConnection.createStatement();
            jadeSignalRows = jadeSignalStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeSignalRows.getRow());
        } finally {
            if (jadeSignalRows != null) {
                jadeSignalRows.close();
            }
            if (jadeSignalStatement != null) {
                jadeSignalStatement.close();
            }
            jadeSignalConnection.close();
        }
    }

    public void runJadeSignal() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = "foo";
        } else {
            data = null;
        }
        queryJadeSignal(data);
    }
}
