import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_AmberGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void runAmberGlint() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_AmberGlintSafeSink()).queryAmberGlint(dataContainer);
    }
}

class CWE89_P09_V2_AmberGlintSafeSink {
    public void queryAmberGlint(CWE89_P09_V2_AmberGlintSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        Statement amberGlintStatement = null;
        ResultSet amberGlintRows = null;
        try {
            amberGlintStatement = amberGlintConnection.createStatement();
            amberGlintRows = amberGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(amberGlintRows.getRow());
        } finally {
            if (amberGlintRows != null) {
                amberGlintRows.close();
            }
            if (amberGlintStatement != null) {
                amberGlintStatement.close();
            }
            amberGlintConnection.close();
        }
    }
}
