import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V1_SaffronQuartz {

    public static String data;

    public void runSaffronQuartz() throws SQLException {
        data = System.getenv("SAFFRON_QUARTZ_FILTER");
        (new CWE89_P10_V1_SaffronQuartzSink()).querySaffronQuartz();
    }
}

class CWE89_P10_V1_SaffronQuartzSink {
    public void querySaffronQuartz() throws SQLException {
        String data = CWE89_P10_V1_SaffronQuartz.data;
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        Statement saffronQuartzStatement = null;
        ResultSet saffronQuartzRows = null;
        try {
            saffronQuartzStatement = saffronQuartzConnection.createStatement();
            saffronQuartzRows = saffronQuartzStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(saffronQuartzRows.getRow());
        } finally {
            if (saffronQuartzRows != null) {
                saffronQuartzRows.close();
            }
            if (saffronQuartzStatement != null) {
                saffronQuartzStatement.close();
            }
            saffronQuartzConnection.close();
        }
    }
}
