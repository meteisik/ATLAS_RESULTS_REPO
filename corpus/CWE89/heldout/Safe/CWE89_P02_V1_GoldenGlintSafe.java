import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_GoldenGlintSafe {

    public void runGoldenGlint() throws SQLException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
    }
}
