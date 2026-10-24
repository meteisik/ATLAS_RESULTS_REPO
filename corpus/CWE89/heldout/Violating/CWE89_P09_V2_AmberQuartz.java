import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberQuartz {
    private static boolean privateTrue = true;

    static class Container {
        public String containerOne;
    }

    public void runAmberQuartz() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_QUARTZ_FILTER");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberQuartzSink()).queryAmberQuartz(dataContainer);
    }
}

class CWE89_P09_V2_AmberQuartzSink {
    public void queryAmberQuartz(CWE89_P09_V2_AmberQuartz.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
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
