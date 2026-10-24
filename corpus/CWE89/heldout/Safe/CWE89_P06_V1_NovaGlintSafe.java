import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V1_NovaGlintSafe {

    public void runNovaGlint() throws SQLException {
        String data;
        data = "foo";
        (new CWE89_P06_V1_NovaGlintSafeSink()).queryNovaGlint(data);
    }
}

class CWE89_P06_V1_NovaGlintSafeSink {
    public void queryNovaGlint(String data) throws SQLException {
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        Statement novaGlintStatement = null;
        ResultSet novaGlintRows = null;
        try {
            novaGlintStatement = novaGlintConnection.createStatement();
            novaGlintRows = novaGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(novaGlintRows.getRow());
        } finally {
            if (novaGlintRows != null) {
                novaGlintRows.close();
            }
            if (novaGlintStatement != null) {
                novaGlintStatement.close();
            }
            novaGlintConnection.close();
        }
    }
}
