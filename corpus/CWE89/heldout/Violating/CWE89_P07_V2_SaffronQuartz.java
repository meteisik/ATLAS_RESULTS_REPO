import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V2_SaffronQuartz {

    public void runSaffronQuartz() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = (new CWE89_P07_V2_SaffronQuartzSource()).loadSaffronQuartz();
        }
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

class CWE89_P07_V2_SaffronQuartzSource {
    public String loadSaffronQuartz() {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_FILTER");
        return data;
    }
}
