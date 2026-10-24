import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneCometSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneComet() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneCometSafeSink()).queryRuneComet(dataContainer);
    }
}

class CWE89_P09_V1_RuneCometSafeSink {
    public void queryRuneComet(CWE89_P09_V1_RuneCometSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        Statement runeCometStatement = null;
        ResultSet runeCometRows = null;
        try {
            runeCometStatement = runeCometConnection.createStatement();
            runeCometRows = runeCometStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeCometRows.getRow());
        } finally {
            if (runeCometRows != null) {
                runeCometRows.close();
            }
            if (runeCometStatement != null) {
                runeCometStatement.close();
            }
            runeCometConnection.close();
        }
    }
}
