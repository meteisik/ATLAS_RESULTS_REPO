import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_GoldenAurora {

    public void runGoldenAurora() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_AURORA_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection goldenAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenAurora");
            Statement goldenAuroraStatement = null;
            ResultSet goldenAuroraRows = null;
            try {
                goldenAuroraStatement = goldenAuroraConnection.createStatement();
                goldenAuroraRows = goldenAuroraStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(goldenAuroraRows.getRow());
            } finally {
                if (goldenAuroraRows != null) {
                    goldenAuroraRows.close();
                }
                if (goldenAuroraStatement != null) {
                    goldenAuroraStatement.close();
                }
                goldenAuroraConnection.close();
            }
        }
    }
}
