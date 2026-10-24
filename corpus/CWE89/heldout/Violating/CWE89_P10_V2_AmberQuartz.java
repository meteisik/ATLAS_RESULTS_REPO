import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AmberQuartz {
    private static int privateFive = 5;

    public static String data;

    public void runAmberQuartz() throws SQLException {
        if (privateFive == 5) {
            data = System.getenv("AMBER_QUARTZ_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AmberQuartzSink()).queryAmberQuartz();
    }
}

class CWE89_P10_V2_AmberQuartzSink {
    public void queryAmberQuartz() throws SQLException {
        String data = CWE89_P10_V2_AmberQuartz.data;
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        Statement amberQuartzStatement = null;
        ResultSet amberQuartzRows = null;
        try {
            amberQuartzStatement = amberQuartzConnection.createStatement();
            amberQuartzRows = amberQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberQuartzRows.getRow());
        } finally {
            if (amberQuartzRows != null) {
                amberQuartzRows.close();
            }
            if (amberQuartzStatement != null) {
                amberQuartzStatement.close();
            }
            amberQuartzConnection.close();
        }
    }
}
