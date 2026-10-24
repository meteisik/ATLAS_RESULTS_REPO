import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronQuartz {

    public void runSaffronQuartz() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SAFFRON_QUARTZ_FILTER");
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P06_V2_SaffronQuartzSink()).querySaffronQuartz(data);
    }
}

class CWE89_P06_V2_SaffronQuartzSink {
    public void querySaffronQuartz(String data) throws SQLException {
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
