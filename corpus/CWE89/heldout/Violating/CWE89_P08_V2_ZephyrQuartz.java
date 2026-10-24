import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V2_ZephyrQuartz {
    private static boolean privateReturnsTrue() { return true; }

    public void runZephyrQuartz() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_QUARTZ_FILTER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V2_ZephyrQuartzSink()).queryZephyrQuartz(dataArray);
    }
}

class CWE89_P08_V2_ZephyrQuartzSink {
    public void queryZephyrQuartz(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection zephyrQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:zephyrQuartz");
        Statement zephyrQuartzStatement = null;
        ResultSet zephyrQuartzRows = null;
        try {
            zephyrQuartzStatement = zephyrQuartzConnection.createStatement();
            zephyrQuartzRows = zephyrQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(zephyrQuartzRows.getRow());
        } finally {
            if (zephyrQuartzRows != null) {
                zephyrQuartzRows.close();
            }
            if (zephyrQuartzStatement != null) {
                zephyrQuartzStatement.close();
            }
            zephyrQuartzConnection.close();
        }
    }
}
