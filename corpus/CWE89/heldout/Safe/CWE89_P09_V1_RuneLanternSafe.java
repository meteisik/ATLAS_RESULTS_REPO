import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneLanternSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneLantern() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneLanternSafeSink()).queryRuneLantern(dataContainer);
    }
}

class CWE89_P09_V1_RuneLanternSafeSink {
    public void queryRuneLantern(CWE89_P09_V1_RuneLanternSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        Statement runeLanternStatement = null;
        ResultSet runeLanternRows = null;
        try {
            runeLanternStatement = runeLanternConnection.createStatement();
            runeLanternRows = runeLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeLanternRows.getRow());
        } finally {
            if (runeLanternRows != null) {
                runeLanternRows.close();
            }
            if (runeLanternStatement != null) {
                runeLanternStatement.close();
            }
            runeLanternConnection.close();
        }
    }
}
