import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P03_V1_GoldenGlint {

    private void queryGoldenGlint(String data) throws SQLException {
        Connection goldenGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenGlint");
        Statement goldenGlintStatement = null;
        ResultSet goldenGlintRows = null;
        try {
            goldenGlintStatement = goldenGlintConnection.createStatement();
            goldenGlintRows = goldenGlintStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(goldenGlintRows.getRow());
        } finally {
            if (goldenGlintRows != null) {
                goldenGlintRows.close();
            }
            if (goldenGlintStatement != null) {
                goldenGlintStatement.close();
            }
            goldenGlintConnection.close();
        }
    }

    public void runGoldenGlint() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_GLINT_FILTER");
        queryGoldenGlint(data);
    }
}
