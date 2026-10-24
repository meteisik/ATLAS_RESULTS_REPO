import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_NovaGlintSafe {

    private String novaGlintData;

    private void queryNovaGlint() throws SQLException {
        String data = novaGlintData;
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

    public void runNovaGlint() throws SQLException {
        String data;
        data = "foo";
        novaGlintData = data;
        queryNovaGlint();
    }
}
