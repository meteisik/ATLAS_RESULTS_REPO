import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_SaffronQuartz {

    static class Container {
        public String containerOne;
    }

    public void runSaffronQuartz() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_FILTER");
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_SaffronQuartzSink()).querySaffronQuartz(dataContainer);
    }
}

class CWE89_P09_V1_SaffronQuartzSink {
    public void querySaffronQuartz(CWE89_P09_V1_SaffronQuartz.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
