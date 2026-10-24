import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P09_V2_VividGlintSafe {

    static class Container {
        public String containerOne;
    }

    public void runVividGlint() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = "foo";
            break;
        default:
            data = null;
            break;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE89_P09_V2_VividGlintSafeSink()).queryVividGlint(dataContainer);
    }
}

class CWE89_P09_V2_VividGlintSafeSink {
    public void queryVividGlint(CWE89_P09_V2_VividGlintSafe.Container dataContainer) throws SQLException {
        String data = dataContainer.containerOne;
        Connection vividGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividGlint");
        Statement vividGlintStatement = null;
        ResultSet vividGlintRows = null;
        try {
            vividGlintStatement = vividGlintConnection.createStatement();
            vividGlintRows = vividGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(vividGlintRows.getRow());
        } finally {
            if (vividGlintRows != null) {
                vividGlintRows.close();
            }
            if (vividGlintStatement != null) {
                vividGlintStatement.close();
            }
            vividGlintConnection.close();
        }
    }
}
