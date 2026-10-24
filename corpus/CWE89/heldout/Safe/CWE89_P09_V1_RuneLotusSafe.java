import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V1_RuneLotusSafe {

    static class Container {
        public String containerOne;
    }

    public void runRuneLotus() throws SQLException {
        String data;
        data = "foo";
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V1_RuneLotusSafeSink()).queryRuneLotus(dataContainer);
    }
}

class CWE89_P09_V1_RuneLotusSafeSink {
    public void queryRuneLotus(CWE89_P09_V1_RuneLotusSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        Statement runeLotusStatement = null;
        ResultSet runeLotusRows = null;
        try {
            runeLotusStatement = runeLotusConnection.createStatement();
            runeLotusRows = runeLotusStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(runeLotusRows.getRow());
        } finally {
            if (runeLotusRows != null) {
                runeLotusRows.close();
            }
            if (runeLotusStatement != null) {
                runeLotusStatement.close();
            }
            runeLotusConnection.close();
        }
    }
}
