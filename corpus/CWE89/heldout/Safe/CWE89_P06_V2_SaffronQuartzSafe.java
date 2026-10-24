import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_SaffronQuartzSafe {

    public void runSaffronQuartz() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        (new CWE89_P06_V2_SaffronQuartzSafeSink()).querySaffronQuartz(data);
    }
}

class CWE89_P06_V2_SaffronQuartzSafeSink {
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
