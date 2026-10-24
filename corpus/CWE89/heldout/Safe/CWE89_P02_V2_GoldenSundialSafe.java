import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V2_GoldenSundialSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void runGoldenSundial() throws SQLException {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection goldenSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSundial");
            Statement goldenSundialStatement = null;
            ResultSet goldenSundialRows = null;
            try {
                goldenSundialStatement = goldenSundialConnection.createStatement();
                goldenSundialRows = goldenSundialStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(goldenSundialRows.getRow());
            } finally {
                if (goldenSundialRows != null) {
                    goldenSundialRows.close();
                }
                if (goldenSundialStatement != null) {
                    goldenSundialStatement.close();
                }
                goldenSundialConnection.close();
            }
        }
    }
}
