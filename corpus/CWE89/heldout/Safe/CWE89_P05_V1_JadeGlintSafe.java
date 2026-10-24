import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V1_JadeGlintSafe {

    private String jadeGlintData;

    private void queryJadeGlint() throws SQLException {
        String data = jadeGlintData;
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        Statement jadeGlintStatement = null;
        ResultSet jadeGlintRows = null;
        try {
            jadeGlintStatement = jadeGlintConnection.createStatement();
            jadeGlintRows = jadeGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(jadeGlintRows.getRow());
        } finally {
            if (jadeGlintRows != null) {
                jadeGlintRows.close();
            }
            if (jadeGlintStatement != null) {
                jadeGlintStatement.close();
            }
            jadeGlintConnection.close();
        }
    }

    public void runJadeGlint() throws SQLException {
        String data;
        data = "foo";
        jadeGlintData = data;
        queryJadeGlint();
    }
}
