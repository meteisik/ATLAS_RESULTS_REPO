import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V1_AmberGlint {

    public void runAmberGlint() throws SQLException {
        String data;
        data = System.getenv("AMBER_GLINT_FILTER");
        CWE89_P12_V1_AmberGlintBase baseObject = new CWE89_P12_V1_AmberGlintSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V1_AmberGlintBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V1_AmberGlintSink extends CWE89_P12_V1_AmberGlintBase {
    public void action(String data) throws SQLException {
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
