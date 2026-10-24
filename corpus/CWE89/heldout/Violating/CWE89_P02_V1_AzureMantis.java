import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P02_V1_AzureMantis {

    public void runAzureMantis() throws SQLException {
        String dataCopy;
        {
            String data;
            data = System.getenv("AZURE_MANTIS_FILTER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
            Statement azureMantisStatement = null;
            ResultSet azureMantisRows = null;
            try {
                azureMantisStatement = azureMantisConnection.createStatement();
                azureMantisRows = azureMantisStatement.executeQuery("select * from users where name='" + data + "'");
                System.out.println(azureMantisRows.getRow());
            } finally {
                if (azureMantisRows != null) {
                    azureMantisRows.close();
                }
                if (azureMantisStatement != null) {
                    azureMantisStatement.close();
                }
                azureMantisConnection.close();
            }
        }
    }
}
